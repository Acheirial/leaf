//! XTLS vision padding, as used by the `xtls-rprx-vision` VLESS flow.
//!
//! This is a direct port of `XtlsPadding` / `XtlsUnpadding` from
//! `Xray-core/proxy/proxy.go`. A vision block is:
//!
//! ```text
//! [user id:16]?[command:1][content len:2][padding len:2][content][padding]
//! ```
//!
//! The user id prefixes only the very first block of a connection. Commands
//! are `0` (padding continues), `1` (padding ends) and `2` (padding ends and
//! the reader switches to a raw copy).
//!
//! Vision exists to reshape the first packets of a connection. It only makes
//! sense when both peers agree on the flow; without it both directions are a
//! plain byte stream.

use rand::Rng;

pub const CMD_CONTINUE: u8 = 0;
pub const CMD_END: u8 = 1;
pub const CMD_DIRECT: u8 = 2;

/// A vision block adds at most this much before its content.
const HEADER_LEN: usize = 16 + 1 + 2 + 2;

/// The buffer size Xray uses as the upper bound for a block.
const BLOCK_SIZE: usize = 8192;

/// Default test seed, as used by Xray when the user does not override it.
pub const DEFAULT_TESTSEED: [u32; 4] = [900, 500, 900, 256];

/// Wraps `content` into a vision block.
///
/// `user_uuid` carries the user id that still has to be prefixed, and is
/// cleared after the first block.
pub fn xtls_padding(
    content: &[u8],
    command: u8,
    user_uuid: &mut Option<[u8; 16]>,
    long_padding: bool,
    testseed: &[u32; 4],
) -> Vec<u8> {
    let content_len = content.len();
    let mut rng = rand::thread_rng();
    let mut padding_len: i64 = if (content_len as u32) < testseed[0] && long_padding {
        rng.gen_range(0..testseed[1] as i64) + testseed[2] as i64 - content_len as i64
    } else {
        rng.gen_range(0..testseed[3] as i64)
    };
    let max_padding = BLOCK_SIZE as i64 - HEADER_LEN as i64 - content_len as i64;
    if padding_len > max_padding {
        padding_len = max_padding;
    }
    if padding_len < 0 {
        padding_len = 0;
    }
    let padding_len = padding_len as usize;

    let mut out = Vec::with_capacity(HEADER_LEN + content_len + padding_len);
    if let Some(uuid) = user_uuid.take() {
        out.extend_from_slice(&uuid);
    }
    out.push(command);
    out.push((content_len >> 8) as u8);
    out.push(content_len as u8);
    out.push((padding_len >> 8) as u8);
    out.push(padding_len as u8);
    out.extend_from_slice(content);
    out.resize(out.len() + padding_len, 0);
    out
}

/// Adds vision padding to a stream as it is written.
pub struct Padder {
    enabled: bool,
    user_uuid: Option<[u8; 16]>,
    /// Whether blocks are still long-padded. Xray long-pads while the outer
    /// connection is TLS (`longPadding := w.trafficState.IsTLS`,
    /// `Xray-core/proxy/proxy.go:364`) and unconditionally long-pads the empty
    /// block that hides the VLESS header (`proxy.go:360`). leaf cannot see the
    /// TLS record boundary through `ProxyStream`, so it uses the equivalent
    /// minimal signal: the leading blocks — the empty camouflage block and the
    /// first block that carries content — are long-padded, and the padding
    /// becomes short afterwards. The empty camouflage block is emitted by the
    /// outbound handler when no payload arrives within 500ms (see
    /// `FIRST_PAYLOAD_TIMEOUT` in `vless/outbound/stream.rs`, mirroring
    /// `Xray-core/proxy/vless/outbound/outbound.go:334-352`), reaching this
    /// type as an empty `pad` call.
    long_padding: bool,
    testseed: [u32; 4],
}

impl Padder {
    pub fn new(user_uuid: [u8; 16]) -> Self {
        Padder {
            enabled: true,
            user_uuid: Some(user_uuid),
            long_padding: true,
            testseed: DEFAULT_TESTSEED,
        }
    }

    pub fn disabled() -> Self {
        Padder {
            enabled: false,
            user_uuid: None,
            long_padding: false,
            testseed: DEFAULT_TESTSEED,
        }
    }

    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Pads one write. Non-vision streams are passed through untouched.
    pub fn pad(&mut self, content: &[u8]) -> Vec<u8> {
        if !self.enabled {
            return content.to_vec();
        }
        // Everything but a signal to pad an empty packet is sent as a
        // `continue` block; without an outer TLS session there is no point at
        // which the flow would hand over to a raw copy.
        let long = self.long_padding;
        if !content.is_empty() {
            self.long_padding = false;
        }
        xtls_padding(
            content,
            CMD_CONTINUE,
            &mut self.user_uuid,
            long,
            &self.testseed,
        )
    }
}

#[derive(Clone, Copy)]
struct UnpadState {
    remaining_command: i32,
    remaining_content: i32,
    remaining_padding: i32,
    current_command: u8,
}

/// Removes vision padding from a stream as it is read.
pub struct Unpadder {
    enabled: bool,
    user_uuid: [u8; 16],
    state: Option<UnpadState>,
    buffer: Vec<u8>,
    /// Set once a block asked for a raw copy, or once the stream turned out
    /// not to be vision-shaped.
    passthrough: bool,
}

impl Unpadder {
    pub fn new(user_uuid: [u8; 16]) -> Self {
        Unpadder {
            enabled: true,
            user_uuid,
            state: None,
            buffer: Vec::new(),
            passthrough: false,
        }
    }

    pub fn disabled() -> Self {
        Unpadder {
            enabled: false,
            user_uuid: [0u8; 16],
            state: None,
            buffer: Vec::new(),
            passthrough: true,
        }
    }

    pub fn is_passthrough(&self) -> bool {
        self.passthrough
    }

    /// Number of bytes held back waiting for a partial block.
    pub fn buffered(&self) -> usize {
        self.buffer.len()
    }

    /// Removes the padding from `data`, returning the plaintext it contains.
    pub fn unpad(&mut self, data: &[u8]) -> Vec<u8> {
        if !self.enabled || self.passthrough {
            return data.to_vec();
        }
        self.buffer.extend_from_slice(data);
        let mut out = Vec::new();
        let off = self.consume(&mut out);
        self.buffer.drain(..off);
        out
    }

    /// Runs the block state machine over `self.buffer` starting at 0, writing
    /// plaintext into `out`, and returns how many bytes were consumed.
    fn consume(&mut self, out: &mut Vec<u8>) -> usize {
        let mut off = 0usize;
        if self.state.is_none() {
            if self.buffer.len() < HEADER_LEN {
                // Not even the user id and a full block header yet; wait for
                // more before deciding whether this is a vision stream.
                return 0;
            }
            if self.buffer[..16] != self.user_uuid {
                // Not a vision stream. Hand everything through from now on.
                self.passthrough = true;
                out.extend_from_slice(&self.buffer);
                return self.buffer.len();
            }
            off = 16;
            self.state = Some(UnpadState {
                remaining_command: 5,
                remaining_content: -1,
                remaining_padding: -1,
                current_command: 0,
            });
        }

        loop {
            let mut st = self.state.take().expect("state present");
            if off >= self.buffer.len() {
                self.state = Some(st);
                break;
            }
            if st.remaining_command > 0 {
                let byte = self.buffer[off];
                off += 1;
                match st.remaining_command {
                    5 => st.current_command = byte,
                    4 => st.remaining_content = (byte as i32) << 8,
                    3 => st.remaining_content |= byte as i32,
                    2 => st.remaining_padding = (byte as i32) << 8,
                    1 => st.remaining_padding |= byte as i32,
                    _ => {}
                }
                st.remaining_command -= 1;
            } else if st.remaining_content > 0 {
                let available = (self.buffer.len() - off) as i32;
                let take = available.min(st.remaining_content);
                let take = take as usize;
                out.extend_from_slice(&self.buffer[off..off + take]);
                off += take;
                st.remaining_content -= take as i32;
            } else {
                let available = (self.buffer.len() - off) as i32;
                let take = available.min(st.remaining_padding).max(0) as usize;
                off += take;
                st.remaining_padding -= take as i32;
            }

            if st.remaining_command <= 0 && st.remaining_content <= 0 && st.remaining_padding <= 0 {
                if st.current_command == CMD_CONTINUE {
                    st.remaining_command = 5;
                    self.state = Some(st);
                } else {
                    // Block finished. Everything after it is a plain stream:
                    // VLESS only pads the beginning of a connection.
                    self.passthrough = true;
                    if off < self.buffer.len() {
                        out.extend_from_slice(&self.buffer[off..]);
                        off = self.buffer.len();
                    }
                    break;
                }
            } else {
                self.state = Some(st);
            }
        }
        off
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const UUID: [u8; 16] = [
        0x7f, 0x0e, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
        0xee,
    ];

    #[test]
    fn round_trip_one_message() {
        let mut padder = Padder::new(UUID);
        let mut unpadder = Unpadder::new(UUID);
        let wire = padder.pad(b"hello world");
        assert_eq!(unpadder.unpad(&wire), b"hello world");
    }

    /// Reads the padding length out of a vision block. Only the first block of
    /// a connection carries the 16-byte user id before the
    /// `[command:1][content len:2][padding len:2]` header; every later block
    /// starts directly with that header (Xray writes the id once and then
    /// clears it, `Xray-core/proxy/proxy.go:523-526`).
    fn block_padding_len(block: &[u8], user_id_prefixed: bool) -> usize {
        let off = if user_id_prefixed { 16 } else { 0 };
        ((block[off + 3] as usize) << 8) | block[off + 4] as usize
    }

    #[test]
    fn leading_blocks_are_long_padded_then_short() {
        let mut padder = Padder::new(UUID);
        // The empty camouflage block and the first payload block are
        // long-padded (>= testseed[2] - content), later blocks are not.
        let empty = padder.pad(b"");
        assert_eq!(&empty[..16], &UUID[..], "the first block carries the id");
        let empty_pad = block_padding_len(&empty, true);
        assert!(
            empty_pad > 256,
            "empty block padding {} not long",
            empty_pad
        );

        // The user id was consumed by the block above, so this block and the
        // one after it start directly with the five-byte header.
        let first = padder.pad(b"short");
        assert_ne!(
            &first[..16],
            &UUID[..],
            "only the first block carries the id"
        );
        let first_pad = block_padding_len(&first, false);
        assert!(
            first_pad >= 900 - 5,
            "first block padding {} not long",
            first_pad
        );

        let second = padder.pad(b"short");
        let second_pad = block_padding_len(&second, false);
        assert!(
            second_pad < 256,
            "later block padding {} not short",
            second_pad
        );
    }

    #[test]
    fn round_trip_many_messages() {
        let mut padder = Padder::new(UUID);
        let mut unpadder = Unpadder::new(UUID);
        let mut wire = Vec::new();
        wire.extend_from_slice(&padder.pad(b"hello"));
        wire.extend_from_slice(&padder.pad(b""));
        wire.extend_from_slice(&padder.pad(b"world"));
        assert_eq!(unpadder.unpad(&wire), b"helloworld");
    }

    #[test]
    fn round_trip_byte_at_a_time() {
        let mut padder = Padder::new(UUID);
        let mut unpadder = Unpadder::new(UUID);
        let wire = padder.pad(b"streamed");
        let mut out = Vec::new();
        for byte in wire {
            out.extend_from_slice(&unpadder.unpad(&[byte]));
        }
        assert_eq!(out, b"streamed");
    }

    #[test]
    fn non_vision_stream_passes_through() {
        let mut unpadder = Unpadder::new(UUID);
        let data = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
        assert_eq!(unpadder.unpad(data), data);
    }

    #[test]
    fn disabled_padder_and_unpadder_are_identities() {
        let mut padder = Padder::disabled();
        let mut unpadder = Unpadder::disabled();
        let data = b"plain bytes";
        assert_eq!(padder.pad(data), data);
        assert_eq!(unpadder.unpad(data), data);
    }
}
