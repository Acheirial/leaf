//! The server half of `mlkem768x25519plus`
//! (`Xray-core/proxy/vless/encryption/server.go`).

use std::io;

use rand::{rngs::OsRng, RngCore};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::proxy::AnyStream;

use super::common::{
    create_padding, decode_length, encode_length, parse_padding, Aead, AeadKind, AesCtr, MAX_NONCE,
};
use super::scheme::{ServerScheme, XorMode};
use super::stream::{CommonStream, XorStream};
use super::EncryptionError;

use ml_kem::{Decapsulate, KeyExport};

const IV_LEN: usize = 16;
const MLKEM_PUBLIC_KEY_LEN: usize = 1184;
const MLKEM_SEED_LEN: usize = 64;
const MLKEM_CIPHERTEXT_LEN: usize = 1088;
const X25519_LEN: usize = 32;
/// The server's PFS public key on the wire: ML-KEM ciphertext + X25519 public
/// key (the plaintext inside one `pfsKeyExchangeLength` record).
const SERVER_PFS_LEN: usize = MLKEM_CIPHERTEXT_LEN + X25519_LEN;
/// The full server-hello PFS record: the key plus the AEAD tag
/// (`server.go:pfsKeyExchangeLength`).
const SERVER_PFS_EXCHANGE_LEN: usize = SERVER_PFS_LEN + 16;
/// The client's PFS public key on the wire: ML-KEM encapsulation key + X25519
/// public key.
const CLIENT_PFS_LEN: usize = MLKEM_PUBLIC_KEY_LEN + X25519_LEN;
const TICKET_LEN: usize = 16;

enum ServerKey {
    X25519([u8; 32]),
    MlKem(Box<ml_kem::DecapsulationKey<ml_kem::MlKem768>>),
}

/// The server half of a VLESS encryption conversation.
pub struct ServerInstance {
    scheme: ServerScheme,
    keys: Vec<ServerKey>,
    pkeys_bytes: Vec<Vec<u8>>,
    hash32s: Vec<[u8; 32]>,
    relays_length: usize,
    padding_lens: Vec<[i64; 3]>,
    padding_gaps: Vec<[i64; 3]>,
}

impl ServerInstance {
    /// Parses the inbound `decryption` setting (`server.go:Init`).
    pub fn from_decryption(decryption: &str) -> anyhow::Result<Self> {
        let scheme = ServerScheme::parse(decryption)?;
        let (padding_lens, padding_gaps) = parse_padding(&scheme.padding)
            .map_err(|e| anyhow::Error::new(EncryptionError::Invalid(e)))?;

        let mut keys = Vec::with_capacity(scheme.keys.len());
        let mut pkeys_bytes = Vec::with_capacity(scheme.keys.len());
        let mut hash32s = Vec::with_capacity(scheme.keys.len());
        let mut relays_length = 0usize;
        for key in &scheme.keys {
            match key.len() {
                X25519_LEN => {
                    let mut secret = [0u8; 32];
                    secret.copy_from_slice(key);
                    let public = x25519_dalek::x25519(secret, x25519_dalek::X25519_BASEPOINT_BYTES);
                    keys.push(ServerKey::X25519(secret));
                    hash32s.push(*blake3::hash(&public).as_bytes());
                    pkeys_bytes.push(public.to_vec());
                    relays_length += X25519_LEN + 32;
                }
                MLKEM_SEED_LEN => {
                    let seed = ml_kem::Seed::try_from(key.as_slice()).map_err(|_| {
                        anyhow::Error::new(EncryptionError::Invalid(
                            "invalid ML-KEM-768 seed".to_string(),
                        ))
                    })?;
                    let dk = ml_kem::DecapsulationKey::<ml_kem::MlKem768>::from_seed(seed);
                    let ek = dk.encapsulation_key().to_bytes();
                    let public = ek[..].to_vec();
                    hash32s.push(*blake3::hash(&public).as_bytes());
                    pkeys_bytes.push(public);
                    keys.push(ServerKey::MlKem(Box::new(dk)));
                    relays_length += MLKEM_CIPHERTEXT_LEN + 32;
                }
                other => {
                    return Err(anyhow::Error::new(EncryptionError::Invalid(format!(
                        "unsupported server key length {}",
                        other
                    ))))
                }
            }
        }
        relays_length -= 32;

        Ok(ServerInstance {
            scheme,
            keys,
            pkeys_bytes,
            hash32s,
            relays_length,
            padding_lens,
            padding_gaps,
        })
    }

    /// Performs the handshake and wraps `stream` in the record layer
    /// (`server.go:Handshake`).
    pub async fn handshake(&self, mut stream: AnyStream) -> io::Result<AnyStream> {
        let mut rng = OsRng;

        let iv_and_relays = IV_LEN + self.relays_length;
        let mut buf = vec![0u8; iv_and_relays];
        stream.read_exact(&mut buf).await?;
        let iv: [u8; IV_LEN] = buf[..IV_LEN].try_into().unwrap();
        let relays = &mut buf[IV_LEN..];

        // Recover the relay chain and the NFS key (`server.go:151-198`).
        let mut nfs_key = Vec::with_capacity(32);
        {
            let mut offset = 0usize;
            let mut last_ctr: Option<AesCtr> = None;
            for (j, key) in self.keys.iter().enumerate() {
                if let Some(ctr) = last_ctr.as_mut() {
                    ctr.apply(&mut relays[offset..offset + 32]);
                }
                let index = match key {
                    ServerKey::X25519(_) => X25519_LEN,
                    ServerKey::MlKem(_) => MLKEM_CIPHERTEXT_LEN,
                };
                if self.scheme.mode != XorMode::Native {
                    let mut pub_ctr = AesCtr::new(&self.pkeys_bytes[j], &iv);
                    pub_ctr.apply(&mut relays[offset..offset + index]);
                }
                match key {
                    ServerKey::X25519(secret) => {
                        let peer: [u8; 32] =
                            relays[offset..offset + X25519_LEN].try_into().unwrap();
                        if peer[31] > 127 {
                            return Err(io::Error::other(
                                "VLESS encryption: high bit set in the peer X25519 public key",
                            ));
                        }
                        nfs_key = x25519_dalek::x25519(*secret, peer).to_vec();
                    }
                    ServerKey::MlKem(dk) => {
                        let shared = dk
                            .decapsulate_slice(&relays[offset..offset + MLKEM_CIPHERTEXT_LEN])
                            .map_err(|_| {
                                io::Error::other("VLESS encryption: bad relay ciphertext")
                            })?;
                        nfs_key = shared[..].to_vec();
                    }
                }
                if j == self.keys.len() - 1 {
                    break;
                }
                offset += index;
                let mut ctr = AesCtr::new(&nfs_key, &iv);
                ctr.apply(&mut relays[offset..offset + 32]);
                if relays[offset..offset + 32] != self.hash32s[j + 1] {
                    return Err(io::Error::other(
                        "VLESS encryption: unexpected relay chaining hash",
                    ));
                }
                offset += 32;
                last_ctr = Some(ctr);
            }
        }

        // The server guesses AES-GCM and falls back to ChaCha on the first
        // record (`server.go:235-241`).
        let mut use_aes = true;
        let mut nfs_aead = Aead::new(&iv, &nfs_key, AeadKind::Aes256Gcm);
        let mut encrypted_length = vec![0u8; 18];
        stream.read_exact(&mut encrypted_length).await?;
        let decrypted_length = match nfs_aead.open(&encrypted_length, &[]) {
            Some(p) => p,
            None => {
                use_aes = false;
                nfs_aead = Aead::new(&iv, &nfs_key, AeadKind::ChaCha20Poly1305);
                nfs_aead
                    .open(&encrypted_length, &[])
                    .ok_or_else(|| io::Error::other("VLESS encryption: bad handshake length"))?
            }
        };
        let length = decode_length(&decrypted_length[..2]);

        if length == 32 {
            return Err(io::Error::other(
                "VLESS encryption: 0-RTT tickets are not implemented in this build",
            ));
        }
        if length < CLIENT_PFS_LEN + 16 {
            return Err(io::Error::other("VLESS encryption: client hello too short"));
        }

        let mut encrypted_pfs = vec![0u8; length];
        stream.read_exact(&mut encrypted_pfs).await?;
        let client_pfs_public = nfs_aead
            .open(&encrypted_pfs, &[])
            .ok_or_else(|| io::Error::other("VLESS encryption: bad client PFS exchange"))?;

        let ct = {
            let ek_key = ml_kem::Key::<ml_kem::EncapsulationKey<ml_kem::MlKem768>>::try_from(
                &client_pfs_public[..MLKEM_PUBLIC_KEY_LEN],
            )
            .map_err(|_| io::Error::other("VLESS encryption: bad ML-KEM encapsulation key"))?;
            let cek = ml_kem::EncapsulationKey::<ml_kem::MlKem768>::new(&ek_key)
                .map_err(|_| io::Error::other("VLESS encryption: bad ML-KEM encapsulation key"))?;
            let mut m = [0u8; 32];
            rng.fill_bytes(&mut m);
            cek.encapsulate_deterministic(&ml_kem::B32::from(m))
        };
        let (mlkem_ct, mlkem_shared) = ct;
        let client_x: [u8; 32] = client_pfs_public
            [MLKEM_PUBLIC_KEY_LEN..MLKEM_PUBLIC_KEY_LEN + X25519_LEN]
            .try_into()
            .unwrap();
        let mut server_x_sk = [0u8; 32];
        rng.fill_bytes(&mut server_x_sk);
        let server_x_pub = x25519_dalek::x25519(server_x_sk, x25519_dalek::X25519_BASEPOINT_BYTES);
        let x_shared = x25519_dalek::x25519(server_x_sk, client_x);

        let mut pfs_key = Vec::with_capacity(64);
        pfs_key.extend_from_slice(&mlkem_shared[..]);
        pfs_key.extend_from_slice(&x_shared);
        let mut united_key = pfs_key.clone();
        united_key.extend_from_slice(&nfs_key);

        let mut server_pfs_public = Vec::with_capacity(SERVER_PFS_LEN);
        server_pfs_public.extend_from_slice(&mlkem_ct[..]);
        server_pfs_public.extend_from_slice(&server_x_pub);

        let kind = AeadKind::from_use_aes(use_aes);
        let mut c_aead = Aead::new(&server_pfs_public, &united_key, kind);
        let mut peer_aead = Aead::new(&client_pfs_public, &united_key, kind);

        // The ticket (`server.go:266-285`). 0-RTT ticket storage is not
        // implemented; the ticket is still issued so 1-RTT clients can cache
        // the server's advertised lifetime.
        let mut ticket = [0u8; TICKET_LEN];
        rng.fill_bytes(&mut ticket);
        let seconds = if self.scheme.seconds_to == 0 {
            self.scheme.seconds_from * rand_percent() / 100
        } else {
            rand_between(self.scheme.seconds_from, self.scheme.seconds_to)
        };
        ticket[..2].copy_from_slice(&encode_length(seconds.max(0) as usize));

        let (padding_length, mut padding_lens, padding_gaps) =
            create_padding(&self.padding_lens, &self.padding_gaps);
        if padding_lens.is_empty() {
            padding_lens.push(0);
        }
        let mut server_hello = vec![0u8; SERVER_PFS_EXCHANGE_LEN + 32 + padding_length];
        let mut rec = Vec::new();
        nfs_aead.seal_with_nonce(&MAX_NONCE, &mut rec, &server_pfs_public, &[]);
        server_hello[..SERVER_PFS_EXCHANGE_LEN].copy_from_slice(&rec);
        let ticket_base = SERVER_PFS_EXCHANGE_LEN;
        let mut rec = Vec::new();
        c_aead.seal_into(&mut rec, &ticket, &[]);
        server_hello[ticket_base..ticket_base + rec.len()].copy_from_slice(&rec);

        let pad_base = SERVER_PFS_EXCHANGE_LEN + 32;
        let mut rec = Vec::new();
        c_aead.seal_into(&mut rec, &encode_length(padding_length - 18), &[]);
        server_hello[pad_base..pad_base + rec.len()].copy_from_slice(&rec);
        {
            let body = server_hello[pad_base + 18..pad_base + padding_length - 16].to_vec();
            let mut rec = Vec::new();
            c_aead.seal_into(&mut rec, &body, &[]);
            server_hello[pad_base + 18..pad_base + 18 + rec.len()].copy_from_slice(&rec);
        }

        padding_lens[0] += SERVER_PFS_EXCHANGE_LEN + 32;
        let mut cursor = 0usize;
        for (i, l) in padding_lens.iter().enumerate() {
            if *l > 0 {
                let end = cursor + l;
                stream.write_all(&server_hello[cursor..end]).await?;
                cursor = end;
            }
            if let Some(gap) = padding_gaps.get(i) {
                if !gap.is_zero() {
                    tokio::time::sleep(*gap).await;
                }
            }
        }
        stream.flush().await?;

        // Read the client's padding (`server.go:309-321`).
        let mut encrypted_length = vec![0u8; 18];
        stream.read_exact(&mut encrypted_length).await?;
        let decrypted_length = nfs_aead
            .open(&encrypted_length, &[])
            .ok_or_else(|| io::Error::other("VLESS encryption: bad padding length"))?;
        let padding_len = decode_length(&decrypted_length[..2]);
        if padding_len > 0 {
            let mut padding = vec![0u8; padding_len];
            stream.read_exact(&mut padding).await?;
            if nfs_aead.open(&padding, &[]).is_none() {
                return Err(io::Error::other("VLESS encryption: bad client padding"));
            }
        }

        let transport: AnyStream = if self.scheme.mode == XorMode::Random {
            let out_ctr = AesCtr::new(&united_key, &ticket);
            let in_ctr = AesCtr::new(&united_key, &iv);
            Box::new(XorStream::new(stream, out_ctr, in_ctr))
        } else {
            stream
        };

        Ok(Box::new(CommonStream::new(
            transport,
            kind,
            united_key,
            c_aead,
            peer_aead,
            Vec::new(),
        )))
    }
}

fn rand_between(from: i64, to: i64) -> i64 {
    let (from, to) = if from > to { (to, from) } else { (from, to) };
    let d = to - from;
    if d <= 1 {
        return from;
    }
    from + (rand::random::<u64>() % d as u64) as i64
}

fn rand_percent() -> i64 {
    rand_between(50, 100)
}
