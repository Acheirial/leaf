//! The client half of `mlkem768x25519plus`
//! (`Xray-core/proxy/vless/encryption/client.go`).

use std::io;

use rand::{thread_rng, RngCore};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::proxy::AnyStream;

use super::common::{
    create_padding, decode_length, encode_length, parse_padding, Aead, AeadKind, AesCtr,
    MAX_NONCE,
};
use super::scheme::{ClientScheme, XorMode};
use super::stream::{CommonStream, XorStream};
use super::EncryptionError;

use ml_kem::{Decapsulate, KeyExport};

/// The sizes of the client hello (`client.go:76-78`).
const IV_LEN: usize = 16;
const PFS_KEY_EXCHANGE_LEN: usize = 18 + 1184 + 32 + 16;
const MLKEM_ENCAPSULATION_KEY_LEN: usize = 1184;
const MLKEM_CIPHERTEXT_LEN: usize = 1088;
const X25519_LEN: usize = 32;
/// The server's PFS exchange record: ML-KEM ciphertext + X25519 public key + tag.
const SERVER_PFS_LEN: usize = MLKEM_CIPHERTEXT_LEN + X25519_LEN;

/// The client half of a VLESS encryption conversation.
pub struct ClientInstance {
    scheme: ClientScheme,
    hash32s: Vec<[u8; 32]>,
    relays_length: usize,
    padding_lens: Vec<[i64; 3]>,
    padding_gaps: Vec<[i64; 3]>,
}

impl ClientInstance {
    /// Parses the outbound `encryption` setting (`client.go:Init`).
    pub fn from_encryption(encryption: &str) -> anyhow::Result<Self> {
        let scheme = ClientScheme::parse(encryption)?;
        if scheme.seconds > 0 {
            // `0rtt` needs the ticket cache; see `ServerInstance` for the
            // matching server-side limitation.
            return Err(anyhow::Error::new(EncryptionError::Unsupported(
                "mlkem768x25519plus.0rtt is not implemented in this build (use .1rtt); \
                 a concrete 0-RTT ticket is never silently downgraded to a plaintext connection"
                    .to_string(),
            )));
        }
        let (padding_lens, padding_gaps) = parse_padding(&scheme.padding)
            .map_err(|e| anyhow::Error::new(EncryptionError::Invalid(e)))?;

        let mut relays_length = 0usize;
        let mut hash32s = Vec::with_capacity(scheme.keys.len());
        for key in &scheme.keys {
            match key.len() {
                X25519_LEN => relays_length += X25519_LEN + 32,
                MLKEM_ENCAPSULATION_KEY_LEN => relays_length += MLKEM_CIPHERTEXT_LEN + 32,
                other => {
                    return Err(anyhow::Error::new(EncryptionError::Invalid(format!(
                        "unsupported client key length {}",
                        other
                    ))))
                }
            }
            hash32s.push(*blake3::hash(key).as_bytes());
        }
        relays_length -= 32;

        Ok(ClientInstance {
            scheme,
            hash32s,
            relays_length,
            padding_lens,
            padding_gaps,
        })
    }

    /// Performs the 1-RTT handshake and wraps `stream` in the record layer
    /// (`client.go:Handshake`).
    pub async fn handshake(&self, mut stream: AnyStream) -> io::Result<AnyStream> {
        let use_aes = AeadKind::client_default();
        let mut rng = thread_rng();

        let iv_and_relays_length = IV_LEN + self.relays_length;
        let (padding_length, padding_lens, padding_gaps) =
            create_padding(&self.padding_lens, &self.padding_gaps);

        let mut hello =
            vec![0u8; iv_and_relays_length + PFS_KEY_EXCHANGE_LEN + padding_length];
        rng.fill_bytes(&mut hello[..IV_LEN]);
        let iv: [u8; IV_LEN] = hello[..IV_LEN].try_into().unwrap();

        // Build the relay chain and derive the NFS key (`client.go:88-113`).
        let mut nfs_key = Vec::with_capacity(32);
        {
            let relays = &mut hello[IV_LEN..iv_and_relays_length];
            let mut offset = 0usize;
            let mut last_ctr: Option<AesCtr> = None;
            for (j, key) in self.scheme.keys.iter().enumerate() {
                let index = if key.len() == X25519_LEN {
                    X25519_LEN
                } else {
                    MLKEM_CIPHERTEXT_LEN
                };
                if key.len() == X25519_LEN {
                    let mut eph = [0u8; 32];
                    rng.fill_bytes(&mut eph);
                    let pubkey = x25519_dalek::x25519(eph, x25519_dalek::X25519_BASEPOINT_BYTES);
                    relays[offset..offset + 32].copy_from_slice(&pubkey);
                    let server_pub: [u8; 32] = key.as_slice().try_into().unwrap();
                    nfs_key = x25519_dalek::x25519(eph, server_pub).to_vec();
                } else {
                    let ek = encapsulation_key(key)?;
                    let mut m = [0u8; 32];
                    rng.fill_bytes(&mut m);
                    let (ct, shared) = ek.encapsulate_deterministic(&ml_kem::B32::from(m));
                    relays[offset..offset + index].copy_from_slice(ct.as_ref());
                    nfs_key = shared.as_ref().to_vec();
                }
                if self.scheme.mode != XorMode::Native {
                    AesCtr::new(key, &iv).apply(&mut relays[offset..offset + index]);
                }
                if let Some(ctr) = last_ctr.as_mut() {
                    ctr.apply(&mut relays[offset..offset + 32]);
                }
                if j == self.scheme.keys.len() - 1 {
                    break;
                }
                let hash_slot = offset + index;
                relays[hash_slot..hash_slot + 32].copy_from_slice(&self.hash32s[j + 1]);
                let mut ctr = AesCtr::new(&nfs_key, &iv);
                ctr.apply(&mut relays[hash_slot..hash_slot + 32]);
                last_ctr = Some(ctr);
                offset = hash_slot + 32;
            }
        }

        let mut nfs_aead = Aead::new(&iv, &nfs_key, use_aes);

        // The PFS key exchange and padding records (`client.go:126-141`).
        let base = iv_and_relays_length;
        let mut rec = Vec::new();
        nfs_aead.seal_into(&mut rec, &encode_length(PFS_KEY_EXCHANGE_LEN - 18), &[]);
        hello[base..base + rec.len()].copy_from_slice(&rec);

        let (mlkem_dk, mlkem_ek) = mlkem_keypair(&mut rng)?;
        let mut x_sk = [0u8; 32];
        rng.fill_bytes(&mut x_sk);
        let x_pub = x25519_dalek::x25519(x_sk, x25519_dalek::X25519_BASEPOINT_BYTES);

        let mut client_pfs_public = Vec::with_capacity(MLKEM_ENCAPSULATION_KEY_LEN + 32);
        client_pfs_public.extend_from_slice(mlkem_ek.as_ref());
        client_pfs_public.extend_from_slice(&x_pub);
        let mut rec = Vec::new();
        nfs_aead.seal_into(&mut rec, &client_pfs_public, &[]);
        hello[base + 18..base + 18 + rec.len()].copy_from_slice(&rec);

        let pad_base = base + PFS_KEY_EXCHANGE_LEN;
        let mut rec = Vec::new();
        nfs_aead.seal_into(&mut rec, &encode_length(padding_length - 18), &[]);
        hello[pad_base..pad_base + rec.len()].copy_from_slice(&rec);
        {
            let body = hello[pad_base + 18..pad_base + padding_length - 16].to_vec();
            let mut rec = Vec::new();
            nfs_aead.seal_into(&mut rec, &body, &[]);
            hello[pad_base + 18..pad_base + 18 + rec.len()].copy_from_slice(&rec);
        }

        // Fragment the hello with the configured gaps (`client.go:143-153`).
        let mut padding_lens = padding_lens;
        if padding_lens.is_empty() {
            padding_lens.push(0);
        }
        padding_lens[0] += base + PFS_KEY_EXCHANGE_LEN;
        let mut cursor = 0usize;
        for (i, l) in padding_lens.iter().enumerate() {
            if *l > 0 {
                let end = cursor + l;
                stream.write_all(&hello[cursor..end]).await?;
                cursor = end;
            }
            if let Some(gap) = padding_gaps.get(i) {
                if !gap.is_zero() {
                    tokio::time::sleep(*gap).await;
                }
            }
        }
        stream.flush().await?;

        // Read the server's PFS exchange (`client.go:155-176`).
        let mut encrypted_pfs = vec![0u8; SERVER_PFS_LEN + 16];
        stream.read_exact(&mut encrypted_pfs).await?;
        let server_pfs_public = nfs_aead
            .open_with_nonce(&MAX_NONCE, &encrypted_pfs, &[])
            .ok_or_else(|| io::Error::other("VLESS encryption: bad server PFS exchange"))?;

        let mlkem_shared = mlkem_dk
            .decapsulate_slice(&server_pfs_public[..MLKEM_CIPHERTEXT_LEN])
            .map_err(|_| io::Error::other("VLESS encryption: bad ML-KEM ciphertext"))?;
        let server_x: [u8; 32] = server_pfs_public
            [MLKEM_CIPHERTEXT_LEN..MLKEM_CIPHERTEXT_LEN + 32]
            .try_into()
            .unwrap();
        let x_shared = x25519_dalek::x25519(x_sk, server_x);

        let mut pfs_key = Vec::with_capacity(64);
        pfs_key.extend_from_slice(mlkem_shared.as_ref());
        pfs_key.extend_from_slice(&x_shared);
        let mut united_key = pfs_key.clone();
        united_key.extend_from_slice(&nfs_key);

        let mut c_aead = Aead::new(&client_pfs_public, &united_key, use_aes);
        let mut peer_aead = Aead::new(&server_pfs_public, &united_key, use_aes);

        // Ticket and padding (`client.go:178-205`).
        let mut encrypted_ticket = vec![0u8; 32];
        stream.read_exact(&mut encrypted_ticket).await?;
        let ticket = peer_aead
            .open(&encrypted_ticket, &[])
            .ok_or_else(|| io::Error::other("VLESS encryption: bad ticket"))?;
        let _server_seconds = crate::proxy::vless::encryption::common::decode_length(&ticket[..2]);

        let mut encrypted_length = vec![0u8; 18];
        stream.read_exact(&mut encrypted_length).await?;
        let decrypted_length = peer_aead
            .open(&encrypted_length, &[])
            .ok_or_else(|| io::Error::other("VLESS encryption: bad padding length"))?;
        let padding_len = crate::proxy::vless::encryption::common::decode_length(
            &decrypted_length[..2],
        );
        if padding_len > 0 {
            let mut padding = vec![0u8; padding_len];
            stream.read_exact(&mut padding).await?;
            if peer_aead.open(&padding, &[]).is_none() {
                return Err(io::Error::other("VLESS encryption: bad server padding"));
            }
        }

        // `random` mode XORs every record header (`client.go:205-207`).
        let transport: AnyStream = if self.scheme.mode == XorMode::Random {
            let out_ctr = AesCtr::new(&united_key, &iv);
            let in_ctr = AesCtr::new(&united_key, &ticket[..16].try_into().unwrap());
            Box::new(XorStream::new(stream, out_ctr, in_ctr))
        } else {
            stream
        };

        Ok(Box::new(CommonStream::new(
            transport,
            use_aes,
            united_key,
            c_aead,
            peer_aead,
            Vec::new(),
        )))
    }
}

fn encapsulation_key(key: &[u8]) -> io::Result<ml_kem::EncapsulationKey<ml_kem::MlKem768>> {
    let bytes = ml_kem::Key::<ml_kem::EncapsulationKey<ml_kem::MlKem768>>::try_from(key)
        .map_err(|_| io::Error::other("VLESS encryption: invalid ML-KEM-768 encapsulation key"))?;
    ml_kem::EncapsulationKey::<ml_kem::MlKem768>::new(&bytes)
        .map_err(|_| io::Error::other("VLESS encryption: invalid ML-KEM-768 encapsulation key"))
}

/// Generates a fresh ML-KEM-768 keypair from a random seed.
///
/// The seed form is the one the reference server accepts
/// (`server.go:Init`, `mlkem.NewDecapsulationKey768`), and `encapsulate`
/// determinism only needs 32 uniform bytes.
fn mlkem_keypair(
    rng: &mut impl RngCore,
) -> io::Result<(
    ml_kem::DecapsulationKey<ml_kem::MlKem768>,
    ml_kem::EncapsulationKey<ml_kem::MlKem768>,
)> {
    let mut seed = [0u8; 64];
    rng.fill_bytes(&mut seed);
    let seed = ml_kem::Seed::from(seed);
    let dk = ml_kem::DecapsulationKey::<ml_kem::MlKem768>::from_seed(seed);
    let ek = dk.encapsulation_key().clone();
    Ok((dk, ek))
}
