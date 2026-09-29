//! Shared VLESS wire encoding.
//!
//! The request and response headers are the Xray `proxy/vless/encoding`
//! format:
//!
//! ```text
//! request:  [version:1][user id:16][addons len:1][addons][command:1][port:2][addr type:1][addr]
//! response: [version:1][addons len:1][addons]
//! ```
//!
//! Addons are a protobuf `Addons { string Flow = 1; bytes Seed = 2; }`
//! blob; only `Flow` is used by VLESS itself.

use std::io;

use tokio::io::{AsyncRead, AsyncReadExt};

use crate::session::{SocksAddr, SocksAddrWireType};

/// The only request/response version this implementation knows.
pub const VERSION: u8 = 0;

/// Request commands (Xray `protocol.RequestCommand`).
pub const CMD_TCP: u8 = 1;
pub const CMD_UDP: u8 = 2;
pub const CMD_MUX: u8 = 3;
pub const CMD_RVS: u8 = 4;

/// The flow / encryption option strings this implementation understands.
pub const FLOW_VISION: &str = "xtls-rprx-vision";

/// Request header fields that are always present.
const FIXED_LEN: usize = 1 /* version */ + 16 /* id */ + 1 /* addons len */;

/// The `Addons` protobuf message.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Addons {
    pub flow: String,
}

impl Addons {
    pub fn new(flow: &str) -> Self {
        Addons {
            flow: flow.to_string(),
        }
    }

    /// Encodes the protobuf body (no length prefix). An empty flow encodes to
    /// an empty blob, exactly like Xray's `proto.Marshal` of an empty message.
    pub fn encode(&self) -> Vec<u8> {
        if self.flow.is_empty() {
            return Vec::new();
        }
        let bytes = self.flow.as_bytes();
        let mut out = Vec::with_capacity(2 + bytes.len());
        // field 1, wire type 2 (length delimited)
        out.push(0x0a);
        // VLESS stores the length in a single byte, so the flow can never be
        // longer than 255 bytes. A longer flow is a programming error.
        out.push(bytes.len() as u8);
        out.extend_from_slice(bytes);
        out
    }

    /// Writes `[len:1][protobuf]` as it appears inside a header.
    pub fn write_with_len(&self, out: &mut Vec<u8>) {
        let body = self.encode();
        out.push(body.len() as u8);
        out.extend_from_slice(&body);
    }

    /// Decodes a protobuf `Addons` body. Unknown fields are skipped; this is
    /// what protobuf requires of every decoder.
    pub fn decode(bytes: &[u8]) -> io::Result<Addons> {
        let mut addons = Addons::default();
        let mut i = 0usize;
        while i < bytes.len() {
            let key = bytes[i];
            i += 1;
            let field = key >> 3;
            let wire = key & 0x07;
            match wire {
                // varint
                0 => {
                    while i < bytes.len() {
                        let b = bytes[i];
                        i += 1;
                        if b & 0x80 == 0 {
                            break;
                        }
                    }
                }
                // 64-bit
                1 => i += 8,
                // length delimited
                2 => {
                    if i >= bytes.len() {
                        return Err(io::Error::other("truncated addons field length"));
                    }
                    let len = bytes[i] as usize;
                    i += 1;
                    if i + len > bytes.len() {
                        return Err(io::Error::other("truncated addons field value"));
                    }
                    if field == 1 {
                        addons.flow = String::from_utf8(bytes[i..i + len].to_vec())
                            .map_err(|e| io::Error::other(format!("invalid addons flow: {}", e)))?;
                    }
                    i += len;
                }
                // 32-bit
                5 => i += 4,
                // groups are not used by Addons
                _ => return Err(io::Error::other("invalid addons protobuf wire type")),
            }
            if i > bytes.len() {
                return Err(io::Error::other("truncated addons protobuf"));
            }
        }
        Ok(addons)
    }
}

/// A parsed VLESS request header.
#[derive(Debug, Clone)]
pub struct Request {
    pub version: u8,
    pub user: [u8; 16],
    pub addons: Addons,
    pub command: u8,
    /// The address carried by the request. For the multiplexing and reverse
    /// commands this is the synthetic address Xray uses.
    pub destination: SocksAddr,
}

/// Encodes a VLESS request header.
pub fn encode_request_header(
    user: &[u8; 16],
    command: u8,
    destination: &SocksAddr,
    addons: &Addons,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(64);
    out.push(VERSION);
    out.extend_from_slice(user);
    addons.write_with_len(&mut out);
    out.push(command);
    if command != CMD_MUX && command != CMD_RVS {
        destination.write_buf(&mut out, SocksAddrWireType::PortFirst);
    }
    out
}

/// Encodes a VLESS response header.
pub fn encode_response_header(addons: &Addons) -> Vec<u8> {
    let mut out = Vec::with_capacity(2 + addons.flow.len());
    out.push(VERSION);
    addons.write_with_len(&mut out);
    out
}

/// Reads a complete request header from `r`, blocking until it is available.
///
/// Field by field, so it never reads past the header into the payload.
pub async fn read_request<R: AsyncRead + Unpin>(r: &mut R) -> io::Result<Request> {
    let mut head = [0u8; FIXED_LEN];
    r.read_exact(&mut head).await?;
    if head[0] != VERSION {
        return Err(io::Error::other(format!(
            "vless: invalid request version {}",
            head[0]
        )));
    }
    let mut user = [0u8; 16];
    user.copy_from_slice(&head[1..17]);
    let addons_len = head[17] as usize;
    let mut addons_bytes = vec![0u8; addons_len];
    r.read_exact(&mut addons_bytes).await?;
    let addons = Addons::decode(&addons_bytes)?;
    let command = r.read_u8().await?;
    let destination = match command {
        CMD_MUX => SocksAddr::Domain("v1.mux.cool".to_string(), 0),
        CMD_RVS => SocksAddr::Domain("v1.rvs.cool".to_string(), 0),
        CMD_TCP | CMD_UDP => SocksAddr::read_from(r, SocksAddrWireType::PortFirst).await?,
        other => {
            return Err(io::Error::other(format!(
                "vless: invalid request command {}",
                other
            )))
        }
    };
    Ok(Request {
        version: VERSION,
        user,
        addons,
        command,
        destination,
    })
}
