//! The TCP `fragment` mask.
//!
//! On the client's write path it splits the first payload (or a configured
//! range of payloads) into several writes of a configured length, optionally
//! delaying between them, so a single application write leaves as several TCP
//! segments. It never touches the read path.
//!
//! The wire transform is a pure segmentation of the byte stream: the
//! concatenation of what is written is exactly what was handed in, so the peer
//! needs no mask at all to read it. The optional TLS-hello mode instead
//! rewrites each TLS record's length field to the size of the fragment it
//! carries.

use std::collections::VecDeque;
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use serde_derive::Deserialize;
use serde_json::Value;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::proxy::AnyStream;

use super::{Role, TcpMask, TcpMaskFactory};
use crate::proxy::finalmask::{rand_between, FinalmaskError};

#[derive(Clone, Debug)]
struct FragmentConfig {
    packets_from: i64,
    packets_to: i64,
    max_split_min: i64,
    max_split_max: i64,
    lengths: Vec<(i64, i64)>,
    delays: Vec<(i64, i64)>,
}

impl FragmentConfig {
    fn parse(settings: &Value) -> Result<Self, FinalmaskError> {
        #[derive(Deserialize, Default)]
        struct Range {
            #[serde(default)]
            from: i64,
            #[serde(default)]
            to: i64,
        }
        #[derive(Deserialize, Default)]
        #[serde(rename_all = "camelCase")]
        struct Raw {
            #[serde(default)]
            packets: Option<String>,
            #[serde(default)]
            length: Option<Range>,
            #[serde(default)]
            delay: Option<Range>,
            #[serde(default)]
            lengths: Option<Vec<Range>>,
            #[serde(default)]
            delays: Option<Vec<Range>>,
            #[serde(default, alias = "max_split")]
            max_split: Option<Range>,
        }

        let raw: Raw =
            serde_json::from_value(settings.clone()).map_err(|e| FinalmaskError::Invalid {
                mask: "fragment".to_string(),
                reason: e.to_string(),
            })?;

        let (packets_from, packets_to) = parse_packets(raw.packets.as_deref().unwrap_or(""))?;

        let lengths = match raw.lengths {
            Some(list) if !list.is_empty() => {
                list.into_iter().map(|r| (r.from, r.to)).collect::<Vec<_>>()
            }
            _ => {
                let r = raw.length.unwrap_or_default();
                vec![(r.from, r.to)]
            }
        };
        if lengths.last().map(|(min, _)| *min).unwrap_or(0) == 0 {
            return Err(FinalmaskError::Invalid {
                mask: "fragment".to_string(),
                reason: "the last lengths entry must have a non-zero lower bound".to_string(),
            });
        }

        let delays = match raw.delays {
            Some(list) if !list.is_empty() => {
                list.into_iter().map(|r| (r.from, r.to)).collect::<Vec<_>>()
            }
            _ => {
                let r = raw.delay.unwrap_or_default();
                vec![(r.from, r.to)]
            }
        };

        let max_split = raw.max_split.unwrap_or_default();
        Ok(FragmentConfig {
            packets_from,
            packets_to,
            max_split_min: max_split.from,
            max_split_max: max_split.to,
            lengths,
            delays,
        })
    }

    fn length_for_segment(&self, seg: usize) -> (i64, i64) {
        let idx = seg.min(self.lengths.len() - 1);
        self.lengths[idx]
    }

    fn delay_for_segment(&self, seg: usize) -> (i64, i64) {
        let idx = seg.min(self.delays.len() - 1);
        self.delays[idx]
    }

    /// True when the configured delays are the single zero that asks for the
    /// TLS-hello fragments to leave in one write.
    fn merge_tls_hello_segments(&self) -> bool {
        self.delays.len() == 1 && self.delays[0].1 == 0
    }
}

fn parse_packets(packets: &str) -> Result<(i64, i64), FinalmaskError> {
    let trimmed = packets.trim();
    if trimmed.eq_ignore_ascii_case("tlshello") {
        return Ok((0, 1));
    }
    if trimmed.is_empty() {
        return Ok((0, 0));
    }
    if let Ok(value) = trimmed.parse::<i64>() {
        return Ok((value, value));
    }
    let (left, right) = match trimmed.strip_prefix('-') {
        Some(rest) => match rest.find('-') {
            Some(pos) => {
                let left = format!("-{}", &rest[..pos]);
                (left, rest[pos + 1..].to_string())
            }
            None => return Err(range_error()),
        },
        None => match trimmed.split_once('-') {
            Some((left, right)) => (left.to_string(), right.to_string()),
            None => return Err(range_error()),
        },
    };
    match (left.parse::<i64>(), right.parse::<i64>()) {
        (Ok(from), Ok(to)) => Ok((from, to)),
        _ => Err(range_error()),
    }
}

fn range_error() -> FinalmaskError {
    FinalmaskError::Invalid {
        mask: "fragment".to_string(),
        reason: "invalid packets range".to_string(),
    }
}

pub struct FragmentFactory {
    config: FragmentConfig,
}

impl FragmentFactory {
    pub fn new(settings: &Value) -> Result<Self, FinalmaskError> {
        Ok(FragmentFactory {
            config: FragmentConfig::parse(settings)?,
        })
    }
}

impl std::fmt::Debug for FragmentFactory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("FragmentFactory")
    }
}

impl TcpMaskFactory for FragmentFactory {
    fn create(&self, role: Role) -> io::Result<Box<dyn TcpMask>> {
        Ok(Box::new(FragmentMask {
            config: self.config.clone(),
            server: role == Role::Server,
        }))
    }
}

struct FragmentMask {
    config: FragmentConfig,
    #[allow(dead_code)]
    server: bool,
}

impl TcpMask for FragmentMask {
    fn wrap(self: Box<Self>, inner: AnyStream) -> io::Result<AnyStream> {
        Ok(Box::new(FragmentStream {
            inner,
            config: self.config,
            count: 0,
            queue: VecDeque::new(),
            sleep: None,
            active: false,
            accepted: 0,
        }))
    }
}

/// One chunk of wire bytes and the delay to apply after writing it.
struct WireChunk {
    data: Vec<u8>,
    delay_after: Duration,
}

struct FragmentStream {
    inner: AnyStream,
    config: FragmentConfig,
    count: u64,
    /// The wire chunks of the write currently in flight.
    queue: VecDeque<WireChunk>,
    sleep: Option<Pin<Box<tokio::time::Sleep>>>,
    active: bool,
    /// How many bytes of the in-flight write were accepted from the caller.
    accepted: usize,
}

impl FragmentStream {
    /// Builds the wire chunks for one caller write, or returns `None` to write
    /// it through untouched.
    fn plan(&mut self, p: &[u8]) -> Option<Vec<WireChunk>> {
        if p.is_empty() {
            return None;
        }
        if self.config.packets_from == 0 && self.config.packets_to == 1 {
            if self.count != 1 || p.len() <= 5 || p[0] != 22 {
                return None;
            }
            let record_len = 5 + (((p[3] as usize) << 8) | p[4] as usize);
            if p.len() < record_len {
                return None;
            }
            let data = &p[5..record_len];
            let merge = self.config.merge_tls_hello_segments();
            let max_split = rand_between(self.config.max_split_min, self.config.max_split_max);
            let mut chunks: Vec<WireChunk> = Vec::new();
            let mut merged: Vec<u8> = Vec::new();
            let mut from = 0usize;
            let mut split_num = 0i64;
            loop {
                let (min, max) = self.config.length_for_segment(split_num as usize);
                let mut to = from + rand_between(min, max).max(0) as usize;
                if to > data.len() || (max_split > 0 && split_num + 1 >= max_split) {
                    to = data.len();
                }
                let l = to - from;
                let mut buff = vec![0u8; 5 + l];
                buff[..3].copy_from_slice(&p[..3]);
                buff[5..].copy_from_slice(&data[from..to]);
                buff[3] = (l >> 8) as u8;
                buff[4] = l as u8;
                from = to;
                if merge {
                    merged.extend_from_slice(&buff);
                } else {
                    let (dmin, dmax) = self.config.delay_for_segment(split_num as usize);
                    let delay = if dmax > 0 {
                        Duration::from_millis(rand_between(dmin, dmax).max(0) as u64)
                    } else {
                        Duration::ZERO
                    };
                    chunks.push(WireChunk {
                        data: buff,
                        delay_after: delay,
                    });
                }
                split_num += 1;
                if from == data.len() {
                    break;
                }
            }
            if !merged.is_empty() {
                chunks.push(WireChunk {
                    data: merged,
                    delay_after: Duration::ZERO,
                });
            }
            if p.len() > record_len {
                chunks.push(WireChunk {
                    data: p[record_len..].to_vec(),
                    delay_after: Duration::ZERO,
                });
            }
            return Some(chunks);
        }

        if self.config.packets_from != 0
            && (self.count < self.config.packets_from as u64
                || self.count > self.config.packets_to as u64)
        {
            return None;
        }

        let max_split = rand_between(self.config.max_split_min, self.config.max_split_max);
        let mut chunks: Vec<WireChunk> = Vec::new();
        let mut from = 0usize;
        let mut split_num = 0i64;
        loop {
            let (min, max) = self.config.length_for_segment(split_num as usize);
            let mut to = from + rand_between(min, max).max(0) as usize;
            if to > p.len() || (max_split > 0 && split_num + 1 >= max_split) {
                to = p.len();
            }
            let (dmin, dmax) = self.config.delay_for_segment(split_num as usize);
            let delay = if dmax > 0 {
                Duration::from_millis(rand_between(dmin, dmax).max(0) as u64)
            } else {
                Duration::ZERO
            };
            chunks.push(WireChunk {
                data: p[from..to].to_vec(),
                delay_after: delay,
            });
            from = to;
            split_num += 1;
            if from >= p.len() {
                break;
            }
        }
        Some(chunks)
    }

    /// Drives the queued chunks to the inner stream, sleeping between them.
    fn poll_drain(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<usize>> {
        loop {
            if let Some(sleep) = self.sleep.as_mut() {
                match sleep.as_mut().poll(cx) {
                    Poll::Ready(()) => self.sleep = None,
                    Poll::Pending => return Poll::Pending,
                }
            }
            if self
                .queue
                .front()
                .map(|c| c.data.is_empty())
                .unwrap_or(false)
            {
                self.queue.pop_front();
                continue;
            }
            let Some(chunk) = self.queue.front_mut() else {
                self.active = false;
                let accepted = self.accepted;
                self.accepted = 0;
                return Poll::Ready(Ok(accepted));
            };
            match Pin::new(&mut self.inner).poll_write(cx, &chunk.data) {
                Poll::Ready(Ok(0)) => {
                    self.queue.clear();
                    self.active = false;
                    return Poll::Ready(Err(io::Error::other(
                        "fragment: write returned zero bytes",
                    )));
                }
                Poll::Ready(Ok(n)) => {
                    if n == chunk.data.len() {
                        let chunk = self.queue.pop_front().unwrap();
                        if !chunk.delay_after.is_zero() {
                            self.sleep = Some(Box::pin(tokio::time::sleep(chunk.delay_after)));
                        }
                    } else {
                        chunk.data.drain(..n);
                    }
                }
                Poll::Ready(Err(e)) => {
                    self.queue.clear();
                    self.active = false;
                    return Poll::Ready(Err(e));
                }
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl AsyncRead for FragmentStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for FragmentStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if !self.active {
            self.count += 1;
            match self.plan(buf) {
                None => return Pin::new(&mut self.inner).poll_write(cx, buf),
                Some(chunks) => {
                    self.queue = chunks.into();
                    self.active = true;
                    self.accepted = buf.len();
                }
            }
        }
        self.poll_drain(cx)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.active {
            match self.poll_drain(cx) {
                Poll::Ready(Ok(_)) => {}
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}
