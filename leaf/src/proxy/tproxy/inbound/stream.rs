//! TCP handler of the TPROXY inbound.
//!
//! # Requirements
//!
//! This handler is **Linux-only** and needs `iptables`/`nftables` `TPROXY`
//! rules to route traffic to the listener, plus policy routing so that the
//! kernel keeps the original destination on the packet:
//!
//! ```text
//! # IPv4
//! iptables -t mangle -N LEAF
//! iptables -t mangle -A LEAF -d 0.0.0.0/8 -j RETURN
//! iptables -t mangle -A LEAF -d 127.0.0.0/8 -j RETURN
//! iptables -t mangle -A LEAF -d 192.168.0.0/16 -j RETURN
//! iptables -t mangle -A LEAF -p tcp -j TPROXY --on-port 12345 --tproxy-mark 1
//! iptables -t mangle -A PREROUTING -p tcp -j LEAF
//! ip rule add fwmark 1 lookup 100
//! ip route add local 0.0.0.0/0 dev lo table 100
//!
//! # IPv6
//! ip6tables -t mangle -N LEAF6
//! ip6tables -t mangle -A LEAF6 -d ::1/128 -j RETURN
//! ip6tables -t mangle -A LEAF6 -p tcp -j TPROXY --on-port 12345 --tproxy-mark 1
//! ip6tables -t mangle -A PREROUTING -p tcp -j LEAF6
//! ip -6 rule add fwmark 1 lookup 100
//! ip -6 route add local ::/0 dev lo table 100
//! ```
//!
//! An equivalent `nftables` ruleset:
//!
//! ```text
//! nft add table ip leaf
//! nft 'add chain ip leaf prerouting { type filter hook prerouting priority mangle; }'
//! nft add rule ip leaf prerouting fib daddr type local return
//! nft add rule ip leaf prerouting meta l4proto tcp tproxy to :12345 meta mark set 1 accept
//! nft add table ip leaf_route
//! nft 'add chain ip leaf_route output { type route hook output priority mangle; }'
//! nft add rule ip leaf_route output meta mark 1 meta l4proto tcp ct mark set 0x1 accept
//! ip rule add fwmark 1 lookup 100
//! ip route add local 0.0.0.0/0 dev lo table 100
//! ```
//!
//! # Original destination
//!
//! The listener owns the transparent socket and recovers the destination the
//! client dialed before handing the connection to this handler (see
//! `crate::app::inbound::tproxy_listener`), so `sess.destination` is already
//! set when [`InboundStreamHandler::handle`] runs and the handler leaves the
//! stream and the session untouched.

use std::io;

use async_trait::async_trait;

use crate::proxy::*;
use crate::session::Session;

/// The TPROXY TCP handler: a pass-through, the listener has already resolved
/// the original destination and built the session.
pub struct Handler;

impl Handler {
    /// Builds the handler. Fails with [`io::ErrorKind::Unsupported`] on every
    /// platform other than Linux.
    pub fn new() -> io::Result<Self> {
        #[cfg(target_os = "linux")]
        {
            Ok(Handler)
        }
        #[cfg(not(target_os = "linux"))]
        {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "TPROXY TCP is only supported on Linux",
            ))
        }
    }
}

#[async_trait]
impl InboundStreamHandler for Handler {
    async fn handle<'a>(
        &'a self,
        sess: Session,
        stream: AnyStream,
    ) -> std::io::Result<AnyInboundTransport> {
        tracing::trace!("handling tproxy inbound stream");
        Ok(InboundTransport::Stream(stream, sess))
    }
}
