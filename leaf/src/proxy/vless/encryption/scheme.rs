//! Parsing of the `mlkem768x25519plus` configuration strings.
//!
//! The grammar is the one `Xray-core/infra/conf/vless.go` accepts. Parsing is
//! kept separate from the handshake so a bad or unsupported scheme fails at
//! configuration time with a precise error.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;

use super::EncryptionError;

/// How the ephemeral public keys are disguised on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XorMode {
    /// Keys travel as-is.
    Native,
    /// Keys are XORed with a key derived from the server's public key.
    XorPub,
    /// The whole client hello after the first key is XORed.
    Random,
}

impl XorMode {
    fn parse(s: &str) -> Result<Self, EncryptionError> {
        match s {
            "native" => Ok(XorMode::Native),
            "xorpub" => Ok(XorMode::XorPub),
            "random" => Ok(XorMode::Random),
            _ => Err(EncryptionError::Invalid(format!(
                "unknown encryption mode {:?}",
                s
            ))),
        }
    }
}

const SCHEME: &str = "mlkem768x25519plus";

/// A key is either an X25519 key or an ML-KEM-768 key; their encoded sizes
/// tell them apart.
const X25519_KEY: usize = 32;
const MLKEM_PUBLIC_KEY: usize = 1184;
const MLKEM_PRIVATE_SEED: usize = 64;

/// A parsed client (`encryption`) setting.
#[derive(Debug)]
pub struct ClientScheme {
    pub mode: XorMode,
    /// Non-zero enables the 0-RTT ticket cache.
    pub seconds: u32,
    pub padding: String,
    /// Public keys, X25519 (32 bytes) or ML-KEM-768 encapsulation key
    /// (1184 bytes).
    pub keys: Vec<Vec<u8>>,
}

impl ClientScheme {
    pub fn parse(s: &str) -> Result<Self, EncryptionError> {
        let parts: Vec<&str> = s.split('.').collect();
        if parts.len() < 4 || parts[0] != SCHEME {
            return Err(EncryptionError::Invalid(format!(
                "expected a {} scheme, got {:?}",
                SCHEME, s
            )));
        }
        let mode = XorMode::parse(parts[1])?;
        let seconds = match parts[2] {
            "1rtt" => 0,
            "0rtt" => 1,
            other => {
                return Err(EncryptionError::Invalid(format!(
                    "unknown client rtt mode {:?}",
                    other
                )))
            }
        };
        let (padding, keys) = split_padding_and_keys(&parts[3..], &[X25519_KEY, MLKEM_PUBLIC_KEY])?;
        Ok(ClientScheme {
            mode,
            seconds,
            padding,
            keys,
        })
    }

    pub fn mode(&self) -> XorMode {
        self.mode
    }
}

/// A parsed server (`decryption`) setting.
#[derive(Debug)]
pub struct ServerScheme {
    pub mode: XorMode,
    pub seconds_from: i64,
    pub seconds_to: i64,
    pub padding: String,
    /// Private keys, X25519 (32 bytes) or ML-KEM-768 seed (64 bytes).
    pub keys: Vec<Vec<u8>>,
}

impl ServerScheme {
    pub fn parse(s: &str) -> Result<Self, EncryptionError> {
        let parts: Vec<&str> = s.split('.').collect();
        if parts.len() < 4 || parts[0] != SCHEME {
            return Err(EncryptionError::Invalid(format!(
                "expected a {} scheme, got {:?}",
                SCHEME, s
            )));
        }
        let mode = XorMode::parse(parts[1])?;
        let (seconds_from, seconds_to) = parse_seconds(parts[2])?;
        let (padding, keys) =
            split_padding_and_keys(&parts[3..], &[X25519_KEY, MLKEM_PRIVATE_SEED])?;
        Ok(ServerScheme {
            mode,
            seconds_from,
            seconds_to,
            padding,
            keys,
        })
    }

    pub fn mode(&self) -> XorMode {
        self.mode
    }
}

/// Server seconds follow Xray's grammar exactly. `Xray-core/infra/conf/vless.go:121`
/// evaluates `strings.SplitN(strings.TrimSuffix(field, "s"), "-", 2)`, i.e. a
/// single trailing `s` belongs to the *whole* field and is stripped before the
/// field is split on its first `-`. Valid fields are therefore `N`, `Ns`, `N-M`
/// and `N-Ms` — a per-bound suffix such as `Ns-M` or `Ns-Ms` is rejected by
/// `strconv.Atoi` and must be rejected here too. A single value leaves `to` at
/// 0; Xray's server then picks a random value in `[from*0.5, from)` (see
/// `server.go`), so it is not a fixed `from == to` range.
fn parse_seconds(s: &str) -> Result<(i64, i64), EncryptionError> {
    let trimmed = s.strip_suffix('s').unwrap_or(s);
    let mut it = trimmed.splitn(2, '-');
    let from = it
        .next()
        .and_then(|v| v.parse::<i64>().ok())
        .ok_or_else(|| EncryptionError::Invalid(format!("invalid seconds {:?}", s)))?;
    let to = match it.next() {
        Some(v) => v
            .parse::<i64>()
            .map_err(|_| EncryptionError::Invalid(format!("invalid seconds {:?}", s)))?,
        None => 0,
    };
    Ok((from, to))
}

/// The optional padding parameters come first and are short (a few digits and
/// dashes); keys are longer base64url strings. Returns the padding string and
/// the decoded keys.
fn split_padding_and_keys(
    parts: &[&str],
    allowed_key_len: &[usize],
) -> Result<(String, Vec<Vec<u8>>), EncryptionError> {
    let mut split = parts.len();
    for (i, r) in parts.iter().enumerate() {
        if r.len() >= 20 {
            split = i;
            break;
        }
    }
    let padding = parts[..split].join(".");
    let mut keys = Vec::new();
    for r in &parts[split..] {
        let key = URL_SAFE_NO_PAD.decode(r).map_err(|e| {
            EncryptionError::Invalid(format!("invalid encryption key {:?}: {}", r, e))
        })?;
        if !allowed_key_len.contains(&key.len()) {
            return Err(EncryptionError::Invalid(format!(
                "encryption key has unsupported length {}",
                key.len()
            )));
        }
        keys.push(key);
    }
    if keys.is_empty() {
        return Err(EncryptionError::Invalid(
            "the scheme carries no keys".to_string(),
        ));
    }
    Ok((padding, keys))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(n: usize) -> String {
        URL_SAFE_NO_PAD.encode(vec![0xab; n])
    }

    #[test]
    fn client_scheme_without_padding() {
        let s = format!("mlkem768x25519plus.xorpub.0rtt.{}", key(MLKEM_PUBLIC_KEY));
        let scheme = ClientScheme::parse(&s).unwrap();
        assert_eq!(scheme.mode, XorMode::XorPub);
        assert_eq!(scheme.seconds, 1);
        assert_eq!(scheme.padding, "");
        assert_eq!(scheme.keys.len(), 1);
        assert_eq!(scheme.keys[0].len(), MLKEM_PUBLIC_KEY);
    }

    #[test]
    fn server_scheme_with_padding_and_two_keys() {
        // `600-1200s` is the range form the reference accepts: the trailing `s`
        // belongs to the whole field (`infra/conf/vless.go:121`).
        let s = format!(
            "mlkem768x25519plus.random.600-1200s.100-111-1111.50-0-3333.{}.{}",
            key(X25519_KEY),
            key(MLKEM_PRIVATE_SEED)
        );
        let scheme = ServerScheme::parse(&s).unwrap();
        assert_eq!(scheme.mode, XorMode::Random);
        assert_eq!((scheme.seconds_from, scheme.seconds_to), (600, 1200));
        assert_eq!(scheme.padding, "100-111-1111.50-0-3333");
        assert_eq!(scheme.keys.len(), 2);
        assert_eq!(scheme.keys[0].len(), X25519_KEY);
        assert_eq!(scheme.keys[1].len(), MLKEM_PRIVATE_SEED);
    }

    /// The seconds field is parsed exactly as Xray does it
    /// (`Xray-core/infra/conf/vless.go:121`): a single trailing `s` is stripped
    /// from the *whole* field, then the field is split on its first `-`.
    #[test]
    fn server_seconds_grammar() {
        let parse = |seconds: &str| {
            ServerScheme::parse(&format!(
                "mlkem768x25519plus.native.{seconds}.{}",
                key(X25519_KEY)
            ))
            .map(|scheme| (scheme.seconds_from, scheme.seconds_to))
        };

        assert_eq!(parse("600").unwrap(), (600, 0));
        assert_eq!(parse("600s").unwrap(), (600, 0));
        assert_eq!(parse("600-1200").unwrap(), (600, 1200));
        assert_eq!(parse("600-1200s").unwrap(), (600, 1200));

        // Only the whole field may carry the `s` suffix; `strconv.Atoi` rejects
        // a suffixed bound, so the port rejects these too.
        assert!(parse("600s-1200").is_err());
        assert!(parse("600s-1200s").is_err());
        assert!(parse("-1200").is_err());
        assert!(parse("600-").is_err());
        assert!(parse("600-12x").is_err());
        assert!(parse("abc").is_err());
        assert!(parse("").is_err());
    }

    #[test]
    fn rejects_unknown_scheme() {
        assert!(ClientScheme::parse("none").is_err());
        assert!(ServerScheme::parse("mlkem768x25519plus.native.600s").is_err());
        assert!(ServerScheme::parse(&format!(
            "mlkem768x25519plus.bogus.600s.{}",
            key(X25519_KEY)
        ))
        .is_err());
    }

    #[test]
    fn rejects_wrong_key_size() {
        assert!(
            ClientScheme::parse(&format!("mlkem768x25519plus.native.1rtt.{}", key(64))).is_err()
        );
    }
}
