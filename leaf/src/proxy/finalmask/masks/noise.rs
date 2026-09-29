//! The UDP `noise` mask.
//!
//! Before the first real packet to a peer -- and again after a reset interval
//! -- it sends a configured burst of decoy packets, optionally separated by
//! delays. It never changes the payload.

use std::collections::HashMap;
use std::io;
use std::time::{Duration, Instant};

use serde_derive::Deserialize;
use serde_json::Value;

use super::{PacketMeta, Role, UdpMask, UdpMaskFactory};
use crate::proxy::finalmask::{parse_byte_slice, rand_between, rand_bytes_between, FinalmaskError};

#[derive(Clone, Debug)]
struct NoiseItem {
    rand_min: i64,
    rand_max: i64,
    rand_range_min: i64,
    rand_range_max: i64,
    packet: Vec<u8>,
    delay_min: i64,
    delay_max: i64,
}

pub struct NoiseFactory {
    reset_min: i64,
    reset_max: i64,
    items: Vec<NoiseItem>,
}

impl NoiseFactory {
    pub fn new(settings: &Value) -> Result<Self, FinalmaskError> {
        #[derive(Deserialize, Default)]
        struct Range {
            #[serde(default)]
            from: i64,
            #[serde(default)]
            to: i64,
        }
        #[derive(Deserialize, Default)]
        #[serde(rename_all = "camelCase")]
        struct ItemRaw {
            #[serde(default)]
            rand: Option<Range>,
            #[serde(default)]
            rand_range: Option<Range>,
            #[serde(default)]
            r#type: Option<String>,
            #[serde(default)]
            packet: Value,
            #[serde(default)]
            delay: Option<Range>,
        }
        #[derive(Deserialize, Default)]
        struct Raw {
            #[serde(default)]
            reset: Option<Range>,
            #[serde(default)]
            noise: Vec<ItemRaw>,
        }

        let raw: Raw =
            serde_json::from_value(settings.clone()).map_err(|e| FinalmaskError::Invalid {
                mask: "noise".to_string(),
                reason: e.to_string(),
            })?;

        let mut items = Vec::with_capacity(raw.noise.len());
        for item in raw.noise {
            let rand = item.rand.unwrap_or_default();
            if !item.packet.is_null() && rand.to > 0 {
                return Err(FinalmaskError::Invalid {
                    mask: "noise".to_string(),
                    reason: "a noise item sets either packet or a random length".to_string(),
                });
            }
            let rand_range = item.rand_range.unwrap_or(Range { from: 0, to: 255 });
            if rand_range.from < 0 || rand_range.to > 255 || rand_range.from > rand_range.to {
                return Err(FinalmaskError::Invalid {
                    mask: "noise".to_string(),
                    reason: "randRange must be within 0..=255".to_string(),
                });
            }
            let typ = item.r#type.unwrap_or_default();
            let packet = parse_byte_slice(&item.packet, &typ)?;
            let delay = item.delay.unwrap_or_default();
            items.push(NoiseItem {
                rand_min: rand.from,
                rand_max: rand.to,
                rand_range_min: rand_range.from,
                rand_range_max: rand_range.to,
                packet,
                delay_min: delay.from,
                delay_max: delay.to,
            });
        }

        let reset = raw.reset.unwrap_or_default();
        Ok(NoiseFactory {
            reset_min: reset.from,
            reset_max: reset.to,
            items,
        })
    }
}

impl UdpMaskFactory for NoiseFactory {
    fn create(&self, _role: Role) -> io::Result<Box<dyn UdpMask>> {
        Ok(Box::new(NoiseMask {
            reset_min: self.reset_min,
            reset_max: self.reset_max,
            items: self.items.clone(),
            next: HashMap::new(),
        }))
    }
}

struct NoiseMask {
    reset_min: i64,
    reset_max: i64,
    items: Vec<NoiseItem>,
    /// When the next burst is due, per remote address.
    next: HashMap<String, Instant>,
}

impl UdpMask for NoiseMask {
    fn encode(
        &mut self,
        pkt: &[u8],
        meta: &PacketMeta,
        out: &mut dyn FnMut(&[u8]) -> io::Result<()>,
    ) -> io::Result<()> {
        let key = meta.remote.map(|addr| addr.to_string()).unwrap_or_default();
        let now = Instant::now();
        let burst = match self.next.get(&key) {
            None => true,
            Some(deadline) => self.reset_max > 0 && now >= *deadline,
        };
        if burst {
            for item in &self.items {
                if item.rand_max > 0 {
                    let len = rand_between(item.rand_min, item.rand_max).max(0) as usize;
                    let mut decoy = vec![0u8; len];
                    rand_bytes_between(
                        &mut decoy,
                        item.rand_range_min as u8,
                        item.rand_range_max as u8,
                    );
                    out(&decoy)?;
                } else {
                    out(&item.packet)?;
                }
                let delay = rand_between(item.delay_min, item.delay_max).max(0);
                if delay > 0 {
                    // The delay is the mask's, not the caller's: it holds this
                    // one burst back, nothing else.
                    std::thread::sleep(Duration::from_millis(delay as u64));
                }
            }
        }
        let reset = rand_between(self.reset_min, self.reset_max).max(0) as u64;
        self.next.insert(key, now + Duration::from_secs(reset));
        out(pkt)
    }

    fn decode(&mut self, pkt: &[u8], _meta: &PacketMeta) -> io::Result<Option<Vec<u8>>> {
        Ok(Some(pkt.to_vec()))
    }
}
