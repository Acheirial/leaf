//! VLAN fallbacks: when a connection is not a valid VLESS request, splice it
//! to another responder instead of dropping it.
//!
//! The lookup and inheritance rules are `Xray-core/proxy/vless/inbound`.
//! Fallbacks are addressed by `(name, alpn, path)`, where `name` is the TLS
//! server name, `alpn` the negotiated protocol and `path` the first request
//! path of an HTTP request. Missing entries are filled from the more general
//! entries configured alongside them.

use std::collections::HashMap;
use std::io;
use std::net::IpAddr;

use crate::config;
use crate::proxy::AnyStream;
use crate::session::Session;

#[derive(Debug, Clone)]
pub struct Fallback {
    pub name: String,
    pub alpn: String,
    pub path: String,
    pub type_: String,
    pub dest: String,
    pub xver: u32,
}

type AlpnMap = HashMap<String, HashMap<String, Fallback>>;

pub struct Fallbacks {
    map: HashMap<String, AlpnMap>,
}

impl Fallbacks {
    pub fn new(fallbacks: &[config::VlessFallback]) -> anyhow::Result<Self> {
        let mut map: HashMap<String, AlpnMap> = HashMap::new();
        for fb in fallbacks {
            let fallback = Fallback {
                name: fb.name.clone().unwrap_or_default(),
                alpn: fb.alpn.clone().unwrap_or_default(),
                path: fb.path.clone().unwrap_or_default(),
                type_: fb.type_.clone().unwrap_or_default(),
                dest: fb.dest.clone().unwrap_or_default(),
                xver: fb.xver.unwrap_or(0),
            };
            if fallback.xver > 2 {
                return Err(anyhow::anyhow!(
                    "vless fallbacks: invalid PROXY protocol version {}, \"xver\" only accepts 0, 1, 2",
                    fallback.xver
                ));
            }
            if !fallback.path.is_empty() && !fallback.path.starts_with('/') {
                return Err(anyhow::anyhow!(
                    "vless fallbacks: \"path\" must be empty or start with \"/\""
                ));
            }
            if fallback.type_.is_empty() && !fallback.dest.is_empty() {
                return Err(anyhow::anyhow!(
                    "vless fallbacks: please fill in a valid value for every \"dest\""
                ));
            }
            map.entry(fallback.name.clone())
                .or_default()
                .entry(fallback.alpn.clone())
                .or_default()
                .insert(fallback.path.clone(), fallback);
        }

        // Inherit the wildcard name's alpns.
        if let Some(default_names) = map.get("") {
            let alpns: Vec<String> = default_names.keys().cloned().collect();
            for (name, apfb) in map.iter_mut() {
                if name.is_empty() {
                    continue;
                }
                for alpn in &alpns {
                    apfb.entry(alpn.clone()).or_default();
                }
            }
        }
        // Inherit the wildcard alpn's paths within each name.
        for apfb in map.values_mut() {
            let default_paths: Vec<(String, Fallback)> = match apfb.get("") {
                Some(pfb) => pfb.iter().map(|(k, v)| (k.clone(), v.clone())).collect(),
                None => continue,
            };
            for (alpn, pfb) in apfb.iter_mut() {
                if alpn.is_empty() {
                    continue;
                }
                for (path, fb) in &default_paths {
                    pfb.entry(path.clone()).or_insert_with(|| fb.clone());
                }
            }
        }
        // Inherit the wildcard name's paths for every alpn.
        if let Some(default_names) = map.get("") {
            let snapshot: Vec<(String, HashMap<String, Fallback>)> = default_names
                .iter()
                .map(|(alpn, pfb)| {
                    (
                        alpn.clone(),
                        pfb.iter().map(|(k, v)| (k.clone(), v.clone())).collect(),
                    )
                })
                .collect();
            for (name, apfb) in map.iter_mut() {
                if name.is_empty() {
                    continue;
                }
                for (alpn, paths) in &snapshot {
                    let entry = apfb.entry(alpn.clone()).or_default();
                    for (path, fb) in paths {
                        entry.entry(path.clone()).or_insert_with(|| fb.clone());
                    }
                }
            }
        }

        Ok(Fallbacks { map })
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    /// Resolves the fallback for a connection, following the same "most
    /// specific configured entry wins, otherwise the wildcard" rules.
    pub fn select(&self, name: &str, alpn: &str, path: &str) -> Option<&Fallback> {
        let name: &str = if self.map.len() > 1 || !self.map.contains_key("") {
            if !name.is_empty() && !self.map.contains_key(name) {
                let mut best = "";
                for candidate in self.map.keys() {
                    if !candidate.is_empty()
                        && name.contains(candidate.as_str())
                        && candidate.len() > best.len()
                    {
                        best = candidate.as_str();
                    }
                }
                best
            } else {
                name
            }
        } else {
            name
        };
        let name = if self.map.contains_key(name) {
            name
        } else {
            ""
        };
        let apfb = self.map.get(name)?;
        let alpn = if apfb.contains_key(alpn) { alpn } else { "" };
        let pfb = apfb.get(alpn)?;
        let path = if pfb.len() > 1 || !pfb.contains_key("") {
            if pfb.contains_key(path) {
                path
            } else {
                ""
            }
        } else {
            ""
        };
        pfb.get(path)
    }
}

/// Parses the request path out of the first bytes of an HTTP request, the same
/// way Xray does when only a `path` fallback is configured.
pub fn http_path(first: &[u8]) -> String {
    if first.len() < 18 || first[4] == b'*' {
        return String::new();
    }
    for i in 4..=8 {
        if first[i] == b'/' && first[i - 1] == b' ' {
            let search = std::cmp::min(first.len(), 64);
            for j in i + 1..search {
                let k = first[j];
                if k == b'\r' || k == b'\n' {
                    break;
                }
                if k == b'?' || k == b' ' {
                    return String::from_utf8_lossy(&first[i..j]).into_owned();
                }
            }
            break;
        }
    }
    String::new()
}

impl Fallback {
    /// Dials the fallback destination.
    pub async fn dial(&self) -> io::Result<AnyStream> {
        match self.type_.as_str() {
            "tcp" => {
                let stream = tokio::net::TcpStream::connect(&self.dest).await?;
                Ok(Box::new(stream))
            }
            "unix" => {
                #[cfg(unix)]
                {
                    let stream = tokio::net::UnixStream::connect(&self.dest).await?;
                    Ok(Box::new(stream))
                }
                #[cfg(not(unix))]
                {
                    Err(io::Error::other(
                        "unix fallback is not supported on this platform",
                    ))
                }
            }
            other => Err(io::Error::other(format!(
                "unsupported fallback type {:?}",
                other
            ))),
        }
    }

    /// Builds the PROXY protocol header for `xver` 1 or 2.
    pub fn proxy_header(&self, sess: &Session) -> Option<Vec<u8>> {
        match self.xver {
            1 => Some(proxy_v1(sess.source, sess.local_addr)),
            2 => Some(proxy_v2(sess.source, sess.local_addr)),
            _ => None,
        }
    }
}

fn proxy_v1(source: std::net::SocketAddr, local: std::net::SocketAddr) -> Vec<u8> {
    match (source.ip(), local.ip()) {
        (IpAddr::V4(_), IpAddr::V4(_)) => format!(
            "PROXY TCP4 {} {} {} {}\r\n",
            source.ip(),
            local.ip(),
            source.port(),
            local.port()
        )
        .into_bytes(),
        (IpAddr::V6(_), IpAddr::V6(_)) => format!(
            "PROXY TCP6 {} {} {} {}\r\n",
            source.ip(),
            local.ip(),
            source.port(),
            local.port()
        )
        .into_bytes(),
        _ => b"PROXY UNKNOWN\r\n".to_vec(),
    }
}

fn proxy_v2(source: std::net::SocketAddr, local: std::net::SocketAddr) -> Vec<u8> {
    const SIGNATURE: [u8; 12] = [
        0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A,
    ];
    let mut out = Vec::with_capacity(52);
    out.extend_from_slice(&SIGNATURE);
    match (source, local) {
        (std::net::SocketAddr::V4(src), std::net::SocketAddr::V4(local)) => {
            out.extend_from_slice(&[0x21, 0x11, 0x00, 0x0C]);
            out.extend_from_slice(&src.ip().octets());
            out.extend_from_slice(&local.ip().octets());
            out.extend_from_slice(&src.port().to_be_bytes());
            out.extend_from_slice(&local.port().to_be_bytes());
        }
        (std::net::SocketAddr::V6(src), std::net::SocketAddr::V6(local)) => {
            out.extend_from_slice(&[0x21, 0x21, 0x00, 0x24]);
            out.extend_from_slice(&src.ip().octets());
            out.extend_from_slice(&local.ip().octets());
            out.extend_from_slice(&src.port().to_be_bytes());
            out.extend_from_slice(&local.port().to_be_bytes());
        }
        _ => out.extend_from_slice(&[0x20, 0x00, 0x00, 0x00]),
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fb(name: &str, alpn: &str, path: &str, dest: &str) -> config::VlessFallback {
        config::VlessFallback {
            name: Some(name.to_string()),
            alpn: Some(alpn.to_string()),
            path: Some(path.to_string()),
            type_: Some("tcp".to_string()),
            dest: Some(dest.to_string()),
            xver: None,
            ..Default::default()
        }
    }

    #[test]
    fn default_entry_matches_anything() {
        let fallbacks = Fallbacks::new(&[fb("", "", "", "127.0.0.1:80")]).unwrap();
        let got = fallbacks.select("example.com", "h2", "/x").unwrap();
        assert_eq!(got.dest, "127.0.0.1:80");
    }

    #[test]
    fn named_entry_is_substring_matched() {
        let fallbacks = Fallbacks::new(&[
            fb("", "", "", "127.0.0.1:80"),
            fb("example.com", "", "", "127.0.0.1:81"),
        ])
        .unwrap();
        assert_eq!(
            fallbacks.select("www.example.com", "", "").unwrap().dest,
            "127.0.0.1:81"
        );
        assert_eq!(
            fallbacks.select("other.org", "", "").unwrap().dest,
            "127.0.0.1:80"
        );
    }

    #[test]
    fn alpn_and_path_are_inherited() {
        let fallbacks = Fallbacks::new(&[
            fb("", "", "", "127.0.0.1:80"),
            fb("", "", "/ws", "127.0.0.1:81"),
            fb("", "h2", "", "127.0.0.1:82"),
        ])
        .unwrap();
        // The path is only consulted when more than the wildcard path exists.
        assert_eq!(
            fallbacks.select("", "", "/ws").unwrap().dest,
            "127.0.0.1:81"
        );
        assert_eq!(
            fallbacks.select("", "", "/other").unwrap().dest,
            "127.0.0.1:80"
        );
        // The h2 entry has its own default path, and inherits the wildcard one.
        assert_eq!(fallbacks.select("", "h2", "").unwrap().dest, "127.0.0.1:82");
        assert_eq!(
            fallbacks.select("", "h2", "/ws").unwrap().dest,
            "127.0.0.1:81"
        );
    }

    #[test]
    fn http_path_is_parsed() {
        assert_eq!(
            http_path(b"GET /ws?x=1 HTTP/1.1\r\nHost: a\r\n".as_slice()),
            "/ws"
        );
        assert_eq!(http_path(b"not http at all, just bytes"), "");
    }
}
