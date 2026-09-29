//! Linux TPROXY inbound.
//!
//! `TPROXY` hands connections and datagrams whose destination is *not* a local
//! address to a local listener, keeping the original destination intact. The
//! inbound therefore consists of
//!
//! * [`inbound::Handler`], the crate-level inbound handler holding the TCP and
//!   UDP sub-handlers,
//! * [`sys`], the socket plumbing (`IP_TRANSPARENT`,
//!   `IP_RECVORIGDSTADDR`, `SO_ORIGINAL_DST`) that is only implemented on
//!   Linux and returns [`std::io::ErrorKind::Unsupported`] everywhere else,
//! * `crate::app::inbound::tproxy_listener`, which owns the transparent
//!   listener and feeds the dispatcher / NAT manager.
//!
//! See the module documentation of `inbound::stream` and `inbound::datagram`
//! for the required `iptables`/`nftables` and `ip rule` setup.

pub mod inbound;
pub mod sys;
