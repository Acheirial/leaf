//! FinalMask: a per-connection TCP/UDP packet-masking layer that sits below
//! the protocol, like a transport pair (ws/tls).
//!
//! The configuration names a chain of masks for each transport:
//!
//! ```json
//! {
//!   "tcp": [ { "maskType": "fragment", "settings": "{...}" } ],
//!   "udp": [ { "maskType": "salamander", "settings": "{...}" } ]
//! }
//! ```
//!
//! The chain is applied in configuration order, the first entry closest to the
//! application. A mask that is not implemented is rejected when the handler is
//! constructed, never passed through silently.
//!
//! `tcpTemplate`/`udpTemplate` are JSON objects keyed by mask type. They hold
//! default settings for the masks of that transport; a mask's own `settings`
//! are merged over the defaults of the same key. This lets a chain share the
//! common part of a per-mask configuration.

pub mod datagram;
pub mod inbound;
pub mod masks;
pub mod outbound;

use std::io;

use serde_json::Value;

use crate::config;

pub use masks::{
    custom, fragment, noise, salamander, sudoku, PacketMeta, Role, TcpMask, TcpMaskFactory,
    UdpMask, UdpMaskFactory,
};

/// The failure of building a FinalMask chain from its configuration.
#[derive(thiserror::Error, Debug)]
pub enum FinalmaskError {
    #[error("finalmask mask type is missing")]
    MissingType,
    #[error("finalmask mask type [{0}] is not implemented")]
    Unimplemented(String),
    #[error("invalid finalmask [{mask}]: {reason}")]
    Invalid { mask: String, reason: String },
    #[error("invalid finalmask settings json: {0}")]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    Io(#[from] io::Error),
}

/// Parses a template into a JSON object, rejecting anything of another shape.
pub(crate) fn parse_template(template: &Option<String>) -> Result<Option<Value>, FinalmaskError> {
    match template {
        None => Ok(None),
        Some(raw) if raw.trim().is_empty() => Ok(None),
        Some(raw) => {
            let value: Value = serde_json::from_str(raw)?;
            if !value.is_object() {
                return Err(FinalmaskError::Invalid {
                    mask: "template".to_string(),
                    reason: "template must be a JSON object keyed by mask type".to_string(),
                });
            }
            Ok(Some(value))
        }
    }
}

/// The settings of one mask, with its template defaults merged underneath.
fn mask_settings(
    mask: &config::FinalmaskMask,
    template: Option<&Value>,
) -> Result<Value, FinalmaskError> {
    let name = mask.mask_type.clone().unwrap_or_default();
    let mut value = match &mask.settings {
        Some(raw) if !raw.trim().is_empty() => serde_json::from_str(raw)?,
        _ => Value::Object(serde_json::Map::new()),
    };
    if let Some(template) = template {
        if let Some(default) = template.get(&name) {
            value = merge(default.clone(), value);
        }
    }
    Ok(value)
}

/// Deep-merges `over` onto `base`: objects are merged key by key, everything
/// else is replaced by the override.
fn merge(base: Value, over: Value) -> Value {
    match (base, over) {
        (Value::Object(mut base), Value::Object(over)) => {
            for (key, value) in over {
                let merged = match base.remove(&key) {
                    Some(existing) => merge(existing, value),
                    None => value,
                };
                base.insert(key, merged);
            }
            Value::Object(base)
        }
        (_, over) => over,
    }
}

pub(crate) fn build_tcp_factories(
    masks: &[config::FinalmaskMask],
    template: Option<&Value>,
) -> Result<Vec<Box<dyn TcpMaskFactory>>, FinalmaskError> {
    let mut factories: Vec<Box<dyn TcpMaskFactory>> = Vec::with_capacity(masks.len());
    for mask in masks {
        let name = mask.mask_type.clone().ok_or(FinalmaskError::MissingType)?;
        let settings = mask_settings(mask, template)?;
        let factory: Box<dyn TcpMaskFactory> = match name.as_str() {
            "fragment" => Box::new(fragment::FragmentFactory::new(&settings)?),
            "header-custom" => Box::new(custom::TcpFactory::new(&settings)?),
            "sudoku" => Box::new(sudoku::TcpFactory::new(&settings)?),
            _ => return Err(FinalmaskError::Unimplemented(name)),
        };
        factories.push(factory);
    }
    Ok(factories)
}

pub(crate) fn build_udp_factories(
    masks: &[config::FinalmaskMask],
    template: Option<&Value>,
) -> Result<Vec<Box<dyn UdpMaskFactory>>, FinalmaskError> {
    let mut factories: Vec<Box<dyn UdpMaskFactory>> = Vec::with_capacity(masks.len());
    for mask in masks {
        let name = mask.mask_type.clone().ok_or(FinalmaskError::MissingType)?;
        let settings = mask_settings(mask, template)?;
        let factory: Box<dyn UdpMaskFactory> = match name.as_str() {
            "header-custom" => Box::new(custom::UdpFactory::new(&settings)?),
            "salamander" => Box::new(salamander::SalamanderFactory::new(&settings)?),
            "sudoku" => Box::new(sudoku::UdpFactory::new(&settings)?),
            "noise" => Box::new(noise::NoiseFactory::new(&settings)?),
            _ => return Err(FinalmaskError::Unimplemented(name)),
        };
        factories.push(factory);
    }
    Ok(factories)
}

/// A helper shared by the masks: a random number in `[from, to)`, matching
/// Xray's `crypto.RandBetween` (which returns `from` when the range is empty
/// or one wide).
pub(crate) fn rand_between(from: i64, to: i64) -> i64 {
    use rand::Rng;
    let (from, to) = if from > to { (to, from) } else { (from, to) };
    let d = to - from;
    if d <= 1 {
        return from;
    }
    from + rand::thread_rng().gen_range(0..d)
}

/// Fills `buf` with random bytes in `[from, to]`, matching Xray's
/// `crypto.RandBytesBetween`.
pub(crate) fn rand_bytes_between(buf: &mut [u8], from: u8, to: u8) {
    use rand::Rng;
    rand::thread_rng().fill(buf);
    let (from, to) = if from > to { (to, from) } else { (from, to) };
    if to.wrapping_sub(from) == 255 {
        return;
    }
    let width = (to - from) as u16 + 1;
    for b in buf.iter_mut() {
        *b = from + (*b as u16 % width) as u8;
    }
}

/// Reads a byte field the way Xray's `PraseByteSlice` does: an array of
/// numbers, a plain string, or a hex string. `base64` is not part of the
/// supported subset and is rejected by name.
pub(crate) fn parse_byte_slice(value: &Value, typ: &str) -> Result<Vec<u8>, FinalmaskError> {
    match typ.to_ascii_lowercase().as_str() {
        "" | "array" => match value {
            Value::Null => Ok(Vec::new()),
            Value::Array(items) => {
                let mut out = Vec::with_capacity(items.len());
                for item in items {
                    let byte = item.as_u64().ok_or_else(|| FinalmaskError::Invalid {
                        mask: "packet".to_string(),
                        reason: "array packet must hold numbers".to_string(),
                    })?;
                    if byte > 255 {
                        return Err(FinalmaskError::Invalid {
                            mask: "packet".to_string(),
                            reason: "array packet must hold bytes".to_string(),
                        });
                    }
                    out.push(byte as u8);
                }
                Ok(out)
            }
            _ => Err(FinalmaskError::Invalid {
                mask: "packet".to_string(),
                reason: "array packet must be an array".to_string(),
            }),
        },
        "str" => value
            .as_str()
            .map(|s| s.as_bytes().to_vec())
            .ok_or_else(|| FinalmaskError::Invalid {
                mask: "packet".to_string(),
                reason: "str packet must be a string".to_string(),
            }),
        "hex" => {
            let s = value.as_str().ok_or_else(|| FinalmaskError::Invalid {
                mask: "packet".to_string(),
                reason: "hex packet must be a string".to_string(),
            })?;
            decode_hex(s)
        }
        other => Err(FinalmaskError::Invalid {
            mask: "packet".to_string(),
            reason: format!("unsupported packet encoding [{}]", other),
        }),
    }
}

fn decode_hex(s: &str) -> Result<Vec<u8>, FinalmaskError> {
    if s.len() % 2 != 0 {
        return Err(FinalmaskError::Invalid {
            mask: "packet".to_string(),
            reason: "hex packet must have an even length".to_string(),
        });
    }
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(s.len() / 2);
    for pair in bytes.chunks(2) {
        let hi = (pair[0] as char).to_digit(16);
        let lo = (pair[1] as char).to_digit(16);
        match (hi, lo) {
            (Some(hi), Some(lo)) => out.push(((hi << 4) | lo) as u8),
            _ => {
                return Err(FinalmaskError::Invalid {
                    mask: "packet".to_string(),
                    reason: "hex packet has a non-hex digit".to_string(),
                })
            }
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mask(name: &str, settings: Option<&str>) -> config::FinalmaskMask {
        let mut mask = config::FinalmaskMask::new();
        mask.mask_type = Some(name.to_string());
        mask.settings = settings.map(|s| s.to_string());
        mask
    }

    #[test]
    fn an_unimplemented_tcp_mask_is_named() {
        let err = build_tcp_factories(&[mask("realm", None)], None).unwrap_err();
        assert!(matches!(&err, FinalmaskError::Unimplemented(name) if name == "realm"));
    }

    #[test]
    fn an_unimplemented_udp_mask_is_named() {
        let err = build_udp_factories(&[mask("udphop", None)], None).unwrap_err();
        assert!(matches!(&err, FinalmaskError::Unimplemented(name) if name == "udphop"));
    }

    #[test]
    fn a_missing_tcp_mask_type_is_rejected() {
        let err = build_tcp_factories(&[mask("", None)], None).unwrap_err();
        assert!(matches!(&err, FinalmaskError::Unimplemented(_)));
    }

    #[test]
    fn a_template_supplies_the_missing_settings() {
        let template: Value =
            serde_json::from_str(r#"{"salamander":{"password":"finalmask-psk"}}"#).unwrap();
        let built = build_udp_factories(&[mask("salamander", None)], Some(&template));
        assert!(built.is_ok());
    }

    #[test]
    fn a_bad_mask_setting_is_an_error_not_a_passthrough() {
        // fragment needs a length with a non-zero bound; the point of the case
        // is that such a chain is rejected, never passed through.
        let err = build_tcp_factories(&[mask("fragment", Some(r#"{"packets":"1-1"}"#))], None)
            .unwrap_err();
        assert!(matches!(&err, FinalmaskError::Invalid { .. }));
    }
}
