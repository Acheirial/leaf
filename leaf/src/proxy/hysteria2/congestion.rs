//! Congestion control for Hysteria2 connections.
//!
//! Hysteria's own sender ("brutal") paces at the rate negotiated during
//! authentication and ignores loss. quinn has no public hook with those
//! semantics -- its `Controller` trait is implementable, but the RTT estimator
//! its callbacks hand out is not publicly nameable, so a rate-paced sender
//! cannot be expressed from outside quinn. What is available is BBR, which is
//! the reference's own fallback when no bandwidth is known, so BBR is used and
//! the configured bandwidth only seeds its initial window.

use std::sync::Arc;
use std::time::Instant;

use quinn::congestion::{BbrConfig, Controller, ControllerFactory};

/// Lower bound for the initial window: quinn's own recommendation,
/// `max(2 * max_datagram_size, 14720)`.
const MIN_INITIAL_WINDOW: u64 = 14720;
/// Upper bound, so an absurd configured rate cannot make the handshake exceed
/// the peer's receive window.
const MAX_INITIAL_WINDOW: u64 = 1024 * 1024;

#[derive(Debug)]
struct BandwidthBbr {
    initial_window: u64,
}

impl ControllerFactory for BandwidthBbr {
    fn build(self: Arc<Self>, now: Instant, current_mtu: u16) -> Box<dyn Controller> {
        let mut config = BbrConfig::default();
        config.initial_window(self.initial_window);
        Arc::new(config).build(now, current_mtu)
    }
}

/// Builds the congestion controller factory for a link of `bandwidth_bps`
/// bytes per second (0 when unknown).
pub fn factory(bandwidth_bps: u64) -> Arc<dyn ControllerFactory + Send + Sync> {
    if bandwidth_bps == 0 {
        return Arc::new(BbrConfig::default());
    }
    // One tenth of a second of data at the configured rate: a plain, if
    // conservative, translation of a bandwidth into a window.
    let initial_window = (bandwidth_bps / 10).clamp(MIN_INITIAL_WINDOW, MAX_INITIAL_WINDOW);
    Arc::new(BandwidthBbr { initial_window })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn factory_falls_back_to_default_bbr() {
        // Both branches must produce a usable factory.
        let _ = factory(0);
        let _ = factory(100_000_000);
    }
}
