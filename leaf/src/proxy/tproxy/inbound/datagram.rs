//! UDP handler of the TPROXY inbound.
//!
//! # Requirements
//!
//! **Linux-only**: the original destination of a transparently routed datagram
//! is only reported through the `IP_RECVORIGDSTADDR` / `IPV6_RECVORIGDSTADDR`
//! control messages, and replying correctly requires sending from the
//! destination the client dialed, which needs `IP_TRANSPARENT`. Traffic has to
//! be handed to the listener by `iptables`/`nftables` `TPROXY` rules:
//!
//! ```text
//! iptables -t mangle -N LEAF
//! iptables -t mangle -A LEAF -d 0.0.0.0/8 -j RETURN
//! iptables -t mangle -A LEAF -d 127.0.0.0/8 -j RETURN
//! iptables -t mangle -A LEAF -d 192.168.0.0/16 -j RETURN
//! iptables -t mangle -A LEAF -p udp -j TPROXY --on-port 12345 --tproxy-mark 1
//! iptables -t mangle -A PREROUTING -p udp -j LEAF
//! ip rule add fwmark 1 lookup 100
//! ip route add local 0.0.0.0/0 dev lo table 100
//!
//! ip6tables -t mangle -N LEAF6
//! ip6tables -t mangle -A LEAF6 -d ::1/128 -j RETURN
//! ip6tables -t mangle -A LEAF6 -p udp -j TPROXY --on-port 12345 --tproxy-mark 1
//! ip6tables -t mangle -A PREROUTING -p udp -j LEAF6
//! ip -6 rule add fwmark 1 lookup 100
//! ip -6 route add local ::/0 dev lo table 100
//! ```
//!
//! # Reply spoofing
//!
//! The kernel forwards the datagram without rewriting its source or
//! destination, so the upstream sees a connection from the *client*. The reply
//! therefore has to leave with the **original destination** as its source
//! address; this handler keeps one socket per `(client, original destination)`
//! pair, created via [`crate::proxy::tproxy::sys::bind_spoofed_udp`], and sends
//! every reply for that pair through it.

use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use async_trait::async_trait;
use tokio::io::Interest;
use tracing::debug;

use crate::{
    proxy::*,
    session::{DatagramSource, SocksAddr, StreamId},
};

/// The TPROXY UDP handler.
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
                "TPROXY UDP is only supported on Linux",
            ))
        }
    }
}

/// Creates the transparent UDP socket used by this inbound: a socket with
/// `IP_TRANSPARENT`, `IP_RECVORIGDSTADDR` (and `IP_PKTINFO`) set *before*
/// `bind`, in non-blocking mode. See [`crate::proxy::tproxy::sys::udp_socket`].
pub fn udp_socket(addr: &SocketAddr) -> io::Result<tokio::net::UdpSocket> {
    crate::proxy::tproxy::sys::udp_socket(addr)
}

#[async_trait]
impl InboundDatagramHandler for Handler {
    async fn handle<'a>(&'a self, socket: AnyInboundDatagram) -> io::Result<AnyInboundTransport> {
        tracing::trace!("handling tproxy inbound datagram");
        // The listener already built a transparent socket; take the descriptor
        // back so the receive half can call `recvmsg(2)` and read the
        // per-datagram control messages.
        let std_socket = socket.into_std()?;
        // `into_std` hands back a blocking socket; tokio needs non-blocking.
        std_socket.set_nonblocking(true)?;
        let socket = tokio::net::UdpSocket::from_std(std_socket)?;
        Ok(InboundTransport::Datagram(
            Box::new(Datagram { socket }),
            None,
        ))
    }
}

/// Identifies a `(client, original destination)` pair, so that one NAT session
/// and one spoofed reply socket exist per pair.
fn datagram_key(src: SocketAddr, dst: SocketAddr) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    src.hash(&mut hasher);
    dst.hash(&mut hasher);
    hasher.finish()
}

/// A transparent UDP socket that reports the original destination of every
/// datagram and spoofs the source address of every reply.
pub struct Datagram {
    socket: tokio::net::UdpSocket,
}

impl InboundDatagram for Datagram {
    fn split(
        self: Box<Self>,
    ) -> (
        Box<dyn InboundDatagramRecvHalf>,
        Box<dyn InboundDatagramSendHalf>,
    ) {
        let socket = Arc::new(self.socket);
        let send_half = DatagramSendHalf {
            base: socket.clone(),
            spoof: HashMap::new(),
        };
        (Box::new(DatagramRecvHalf(socket)), Box::new(send_half))
    }

    fn into_std(self: Box<Self>) -> io::Result<std::net::UdpSocket> {
        Err(io::Error::other(
            "cannot convert a tproxy datagram into a std UDP socket",
        ))
    }
}

pub struct DatagramRecvHalf(Arc<tokio::net::UdpSocket>);

#[async_trait]
impl InboundDatagramRecvHalf for DatagramRecvHalf {
    async fn recv_from(
        &mut self,
        buf: &mut [u8],
    ) -> ProxyResult<(usize, DatagramSource, SocksAddr)> {
        let socket = self.0.clone();
        // Await readability and retry on `WouldBlock` instead of failing: the
        // synchronous `try_io` surfaces the first `WouldBlock` (whether from an
        // empty readiness flag or from the non-blocking `recvmsg`) as an error,
        // which the datagram dispatcher maps to `DatagramFatal` and uses to end
        // its receive loop — the runner would stop on its first idle poll.
        let (n, source, original_dst) = socket
            .async_io(Interest::READABLE, || {
                crate::proxy::tproxy::sys::recv_from_original_dst(&*socket, buf)
            })
            .await
            .map_err(|e| ProxyError::DatagramFatal(e.into()))?;
        let key = datagram_key(source, original_dst);
        Ok((
            n,
            DatagramSource::new(source, Some(StreamId::U64(key))),
            SocksAddr::Ip(original_dst),
        ))
    }
}

/// A spoofed reply socket together with the instant it was last used.
struct SpoofEntry {
    socket: tokio::net::UdpSocket,
    last_used: std::time::Instant,
}

pub struct DatagramSendHalf {
    base: Arc<tokio::net::UdpSocket>,
    /// One socket per `(client, original destination)` pair, bound to the
    /// original destination so replies appear to come from it.
    ///
    /// Eviction: each entry records when it was last used and is dropped (its
    /// file descriptor closed) once idle for longer than the UDP session
    /// timeout `crate::option::UDP_SESSION_TIMEOUT`, matching the NAT session
    /// lifetime. The sweep runs opportunistically when a *new* pair is inserted,
    /// via `HashMap::retain` (which allocates nothing), so traffic from many
    /// distinct pairs cannot grow the map or the process's fd table without
    /// bound.
    spoof: HashMap<(SocketAddr, SocketAddr), SpoofEntry>,
}

#[async_trait]
impl InboundDatagramSendHalf for DatagramSendHalf {
    async fn send_to(
        &mut self,
        buf: &[u8],
        src_addr: &SocksAddr,
        dst_addr: &SocketAddr,
    ) -> io::Result<usize> {
        // `src_addr` is the origin the datagram claims, i.e. the address the
        // client originally targeted; `dst_addr` is the client itself.
        let original_dst = match src_addr {
            SocksAddr::Ip(addr) => *addr,
            SocksAddr::Domain(..) => return self.base.send_to(buf, dst_addr).await,
        };
        if original_dst.ip().is_unspecified() {
            return self.base.send_to(buf, dst_addr).await;
        }
        let key = (*dst_addr, original_dst);
        let now = std::time::Instant::now();
        // Existing pair: reuse its spoofed socket and refresh last-used.
        if let Some(entry) = self.spoof.get_mut(&key) {
            entry.last_used = now;
            return entry.socket.send_to(buf, dst_addr).await;
        }
        // New pair: opportunistically evict entries whose NAT session has
        // already expired before inserting, keeping the map (and its fds)
        // bounded. `retain` allocates nothing.
        let timeout = std::time::Duration::from_secs(*crate::option::UDP_SESSION_TIMEOUT);
        self.spoof
            .retain(|_, entry| now.duration_since(entry.last_used) < timeout);
        match crate::proxy::tproxy::sys::bind_spoofed_udp(&original_dst) {
            Ok(socket) => {
                self.spoof.insert(
                    key,
                    SpoofEntry {
                        socket,
                        last_used: now,
                    },
                );
            }
            Err(e) => {
                debug!(
                    "tproxy: failed to bind spoofed udp socket for {}: {}",
                    original_dst, e
                );
                return self.base.send_to(buf, dst_addr).await;
            }
        }
        let entry = self.spoof.get(&key).expect("spoofed socket inserted above");
        entry.socket.send_to(buf, dst_addr).await
    }

    async fn close(&mut self) -> io::Result<()> {
        Ok(())
    }
}
