use std::{
    io::{Error, Result},
    sync::Arc,
};

use async_socks5::{AddrKind, Auth, SocksDatagram};
use async_trait::async_trait;
use bytes::{BufMut, BytesMut};
use futures::future::TryFutureExt;
use tokio::io::{AsyncRead, AsyncWrite};

use crate::{app::SyncDnsClient, common::resolver::Resolver, proxy::*, session::*};

pub struct Handler {
    pub address: String,
    pub port: u16,
    pub username: String,
    pub password: String,
    pub dns_client: SyncDnsClient,
}

impl TcpConnector for Handler {}
impl UdpConnector for Handler {}

impl Handler {
    /// The socks5 server the payload is sent to over the transport a chain
    /// handed this actor: the endpoint its settings name.
    ///
    /// An actor that names nothing is the payload half of a chain, which rides
    /// the transport the chain hands it and has no server of its own; a dial
    /// of it could only fail, and it must not silently become something else.
    fn framed_endpoint(&self) -> io::Result<SocksAddr> {
        if self.address.is_empty() {
            return Err(Error::new(
                std::io::ErrorKind::InvalidInput,
                "no socks5 server address to send the payload to",
            ));
        }
        Ok(match self.address.parse::<IpAddr>() {
            Ok(ip) => SocksAddr::Ip(SocketAddr::new(ip, self.port)),
            Err(_) => SocksAddr::Domain(self.address.clone(), self.port),
        })
    }
}

#[async_trait]
impl OutboundDatagramHandler for Handler {
    fn connect_addr(&self) -> OutboundConnect {
        OutboundConnect::Proxy(Network::Udp, self.address.clone(), self.port)
    }

    fn transport_type(&self) -> DatagramTransportType {
        DatagramTransportType::Unreliable
    }

    async fn handle<'a>(
        &'a self,
        sess: &'a Session,
        transport: Option<AnyOutboundTransport>,
    ) -> io::Result<AnyOutboundDatagram> {
        tracing::trace!("handling outbound datagram");
        // A chain hands this actor the datagram the actors before it produced:
        // the payload rides inside it as socks5 UDP requests. This is what
        // puts the payload in a chain at all -- dialling the endpoint named
        // here instead would bypass every actor before this one, and the
        // payload half of a chain names none.
        if let Some(OutboundTransport::Datagram(carrier)) = transport {
            return Ok(Box::new(Socks5Datagram {
                inner: carrier,
                server: self.framed_endpoint()?,
            }));
        }
        // Nothing was handed to this actor, or what was handed to it is a
        // stream: this actor is the one talking to a socks5 server, which
        // means the associate request and the relay it names.
        let stream = self
            .new_tcp_stream(self.dns_client.clone(), &self.address, &self.port)
            .await?;
        let mut indicator = sess.source;
        if let Ok(ip) = self.address.parse::<IpAddr>() {
            if ip.is_loopback() {
                indicator = SocketAddr::new(ip, 0);
            }
        }
        let socket = self.new_udp_socket(&indicator).await?;

        // Resolve the SOCKS server address to IP (handles both IP and domain names)
        let mut resolver = Resolver::new(self.dns_client.clone(), &self.address, &self.port)
            .await
            .map_err(|e| Error::other(format!("resolve SOCKS server address failed: {}", e)))?;
        let server_addr = resolver
            .next()
            .ok_or_else(|| Error::other("no resolved address for SOCKS server"))?;

        let auth = match (&self.username, &self.password) {
            (auth_username, _) if auth_username.is_empty() => None,
            (auth_username, auth_password) => Some(Auth {
                username: auth_username.to_owned(),
                password: auth_password.to_owned(),
            }),
        };

        let socket = SocksDatagram::associate(stream, socket, auth, server_addr.into())
            .map_err(Error::other)
            .await?;
        Ok(Box::new(Datagram { socket }))
    }
}

/// Carries the payload as socks5 UDP requests over the datagram a chain handed
/// this actor, and takes the replies apart the same way.
///
/// The layout is the one a socks5 UDP request has on the wire: `RSV(2) |
/// FRAG(1) | address | payload`, the address being where the payload is meant
/// to go, and the requests going to the endpoint named by the settings -- the
/// actor that takes them apart, which is the socks5 server. A server that
/// demands an association first cannot be reached this way, but the transport
/// a chain hands a payload actor is a datagram and there is nowhere to put an
/// associate request; that is the trade the chain makes.
pub struct Socks5Datagram {
    inner: AnyOutboundDatagram,
    server: SocksAddr,
}

impl OutboundDatagram for Socks5Datagram {
    fn split(
        self: Box<Self>,
    ) -> (
        Box<dyn OutboundDatagramRecvHalf>,
        Box<dyn OutboundDatagramSendHalf>,
    ) {
        let (recv, send) = self.inner.split();
        (
            Box::new(Socks5DatagramRecvHalf(recv)),
            Box::new(Socks5DatagramSendHalf {
                inner: send,
                server: self.server,
            }),
        )
    }
}

pub struct Socks5DatagramRecvHalf(Box<dyn OutboundDatagramRecvHalf>);

#[async_trait]
impl OutboundDatagramRecvHalf for Socks5DatagramRecvHalf {
    async fn recv_from(&mut self, buf: &mut [u8]) -> Result<(usize, SocksAddr)> {
        // The header is not larger than the address it carries, so a buffer
        // with room for the address can hold the whole frame; anything longer
        // than what was asked for is cut.
        let mut framed = vec![0u8; buf.len() + 512];
        let (n, _) = self.0.recv_from(&mut framed).await?;
        if n < 3 {
            return Err(Error::other(format!(
                "short socks5 UDP request: {} bytes",
                n
            )));
        }
        let addr = SocksAddr::try_from((&framed[3..], SocksAddrWireType::PortLast))
            .map_err(|e| Error::other(format!("parse socks5 UDP address failed: {}", e)))?;
        let header = 3 + addr.size();
        if n < header {
            return Err(Error::other(format!(
                "truncated socks5 UDP request: {} bytes for an address of {}",
                n, header
            )));
        }
        let payload = n - header;
        if buf.len() < payload {
            return Err(Error::other(format!(
                "socks5 UDP payload of {} bytes does not fit in {}",
                payload,
                buf.len()
            )));
        }
        buf[..payload].copy_from_slice(&framed[header..header + payload]);
        Ok((payload, addr))
    }
}

pub struct Socks5DatagramSendHalf {
    inner: Box<dyn OutboundDatagramSendHalf>,
    server: SocksAddr,
}

#[async_trait]
impl OutboundDatagramSendHalf for Socks5DatagramSendHalf {
    async fn send_to(&mut self, buf: &[u8], target: &SocksAddr) -> Result<usize> {
        let mut framed = BytesMut::with_capacity(3 + target.size() + buf.len());
        framed.put_u16(0); // RSV is reserved and zero in every request.
        framed.put_u8(0); // FRAG is zero: this client never fragments.
        target.write_buf(&mut framed, SocksAddrWireType::PortLast);
        framed.put_slice(buf);
        self.inner.send_to(&framed[..], &self.server).await?;
        Ok(buf.len())
    }

    async fn close(&mut self) -> Result<()> {
        self.inner.close().await
    }
}

pub struct Datagram<S> {
    pub socket: SocksDatagram<S>,
}

impl<S> OutboundDatagram for Datagram<S>
where
    S: 'static + AsyncRead + AsyncWrite + Unpin + Send + Sync,
{
    fn split(
        self: Box<Self>,
    ) -> (
        Box<dyn OutboundDatagramRecvHalf>,
        Box<dyn OutboundDatagramSendHalf>,
    ) {
        let rh = Arc::new(self.socket);
        let sh = rh.clone();
        (
            Box::new(DatagramRecvHalf(rh)),
            Box::new(DatagramSendHalf(sh)),
        )
    }
}

pub struct DatagramRecvHalf<S>(Arc<SocksDatagram<S>>);

#[async_trait]
impl<S> OutboundDatagramRecvHalf for DatagramRecvHalf<S>
where
    S: 'static + AsyncRead + AsyncWrite + Send + Unpin + Sync,
{
    async fn recv_from(&mut self, buf: &mut [u8]) -> Result<(usize, SocksAddr)> {
        let (n, addr) = self.0.recv_from(buf).map_err(Error::other).await?;
        match addr {
            AddrKind::Ip(addr) => Ok((n, SocksAddr::Ip(addr))),
            AddrKind::Domain(domain, port) => Ok((n, SocksAddr::Domain(domain, port))),
        }
    }
}

pub struct DatagramSendHalf<S>(Arc<SocksDatagram<S>>);

#[async_trait]
impl<S> OutboundDatagramSendHalf for DatagramSendHalf<S>
where
    S: 'static + AsyncRead + AsyncWrite + Send + Unpin + Sync,
{
    async fn send_to(&mut self, buf: &[u8], target: &SocksAddr) -> Result<usize> {
        match target {
            SocksAddr::Ip(a) => {
                self.0
                    .send_to(buf, a.to_owned())
                    .map_ok(|_| buf.len())
                    .map_err(Error::other)
                    .await
            }
            SocksAddr::Domain(domain, port) => {
                self.0
                    .send_to(buf, (domain.to_owned(), *port))
                    .map_ok(|_| buf.len())
                    .map_err(Error::other)
                    .await
            }
        }
    }

    async fn close(&mut self) -> io::Result<()> {
        // FIXME implement our own socks5 outbound to propagate this.
        Ok(())
    }
}
