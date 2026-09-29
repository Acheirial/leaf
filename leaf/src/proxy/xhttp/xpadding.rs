//! `xPadding`, mirroring Xray's `xpadding.go`.
//!
//! Only the `repeat-x` method produces exact-length padding; `tokenish` would
//! need the HPACK Huffman table to hit a target *compressed* length, so this
//! port treats it as `repeat-x` and validates the raw length. Everything else
//! -- the placements, the default `queryInHeader`/`Referer` request form, the
//! length window -- matches the reference.

use crate::proxy::xhttp::config::{
    Config, PLACEMENT_COOKIE, PLACEMENT_HEADER, PLACEMENT_QUERY, PLACEMENT_QUERY_IN_HEADER,
};
use crate::proxy::xhttp::h1::Request;

const TOLERANCE: i64 = 2;

/// A padding value of exactly `length` bytes. Every method this port supports
/// is `repeat-x`, so the generated length is the wire length.
pub fn generate_padding(length: i64) -> String {
    if length <= 0 {
        return String::new();
    }
    "X".repeat(length as usize)
}

/// The parts of a request `xPadding` was read from, for logging.
pub fn extract_padding(req: &Request, obfs_mode: bool, cfg: &Config) -> (String, String) {
    if !obfs_mode {
        if let Some(referer) = req.header("Referer").filter(|r| !r.is_empty()) {
            let value = referer
                .split_once('?')
                .and_then(|(_, q)| query_get(q, "x_padding"))
                .unwrap_or_default();
            return (value, "queryInHeader=Referer, key=x_padding".to_string());
        }
        let value = req.query_param("x_padding").unwrap_or_default();
        return (value, format!("{}, key=x_padding", PLACEMENT_QUERY));
    }

    let key = cfg.x_padding_key.as_str();
    let header = cfg.x_padding_header.as_str();

    if !key.is_empty() {
        if let Some(value) = cookie_get(req, key).filter(|v| !v.is_empty()) {
            return (value, format!("{}, key={}", PLACEMENT_COOKIE, key));
        }
    }

    if let Some(header_value) = req.header(header).filter(|v| !v.is_empty()) {
        if cfg.x_padding_placement == PLACEMENT_HEADER {
            return (
                header_value.to_string(),
                format!("{}={}", PLACEMENT_HEADER, header),
            );
        }
        if let Some((_, q)) = header_value.split_once('?') {
            return (
                query_get(q, key).unwrap_or_default(),
                format!("{}={}, key={}", PLACEMENT_QUERY_IN_HEADER, header, key),
            );
        }
    }

    if !key.is_empty() {
        if let Some(value) = req.query_param(key) {
            if !value.is_empty() {
                return (value, format!("{}, key={}", PLACEMENT_QUERY, key));
            }
        }
    }

    (String::new(), String::new())
}

pub fn is_padding_valid(method: &str, value: &str, from: i64, to: i64) -> bool {
    if value.is_empty() {
        return false;
    }
    let n = value.len() as i64;
    match method {
        // `tokenish` is treated as `repeat-x`; see the module comment.
        "tokenish" => {
            let f = (from - TOLERANCE).max(0);
            let t = to + TOLERANCE;
            n >= f && n <= t
        }
        _ => to > 0 && n >= from && n <= to,
    }
}

/// The response padding header (or cookie), mirroring
/// `ApplyXPaddingToResponse` with the server's default placement.
pub fn response_padding_headers(cfg: &Config, length: i64) -> Vec<(String, String)> {
    let value = generate_padding(length);
    if value.is_empty() {
        return Vec::new();
    }
    if cfg.x_padding_obfs_mode && cfg.x_padding_placement == PLACEMENT_COOKIE {
        return vec![(
            "Set-Cookie".to_string(),
            format!("{}={}; Path=/", cfg.x_padding_key, value),
        )];
    }
    vec![(cfg.x_padding_header.clone(), value)]
}

fn query_get(query: &str, key: &str) -> Option<String> {
    query.split('&').find_map(|pair| {
        let (k, v) = pair.split_once('=')?;
        if k == key {
            Some(percent_decode(v))
        } else {
            None
        }
    })
}

fn cookie_get(req: &Request, key: &str) -> Option<String> {
    let cookies = req.header("Cookie")?;
    cookies.split(';').find_map(|pair| {
        let (k, v) = pair.trim().split_once('=')?;
        if k == key {
            Some(v.to_string())
        } else {
            None
        }
    })
}

fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let (Some(h), Some(l)) = (hex_val(bytes[i + 1]), hex_val(bytes[i + 2])) {
                out.push(h * 16 + l);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}
