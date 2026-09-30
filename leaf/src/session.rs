use std::{
    borrow::Cow,
    convert::TryFrom,
    fmt, io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6},
    string::ToString,
};

use bytes::BufMut;
use tokio::io::{AsyncRead, AsyncReadExt};

#[derive(PartialEq, Eq, Hash, Clone, Copy, Debug)]
pub enum Network {
    Tcp,
    Udp,
}

impl std::fmt::Display for Network {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::Tcp => write!(f, "tcp"),
            Self::Udp => write!(f, "udp"),
        }
    }
}

#[derive(PartialEq, Eq, Hash, Clone, Copy, Debug)]
pub enum StreamId {
    U64(u64),
    Uuid(uuid::Uuid),
}

impl std::fmt::Display for StreamId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::U64(id) => write!(f, "{}", id),
            Self::Uuid(id) => write!(f, "{}", id),
        }
    }
}

#[derive(PartialEq, Eq, Hash, Clone, Debug)]
pub struct DatagramSource {
    pub address: SocketAddr,
    pub stream_id: Option<StreamId>,
    pub process_name: Option<String>,
}

impl DatagramSource {
    pub fn new(address: SocketAddr, stream_id: Option<StreamId>) -> Self {
        DatagramSource {
            address,
            stream_id,
            process_name: None,
        }
    }

    pub fn new_with_process_name(
        address: SocketAddr,
        stream_id: Option<StreamId>,
        process_name: Option<String>,
    ) -> Self {
        DatagramSource {
            address,
            stream_id,
            process_name,
        }
    }
}

impl std::fmt::Display for DatagramSource {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if let Some(id) = self.stream_id.as_ref() {
            write!(f, "{}(stream-{})", self.address, id)
        } else {
            write!(f, "{}", self.address)
        }
    }
}

#[derive(Debug)]
pub struct Session {
    pub span: tracing::Span,
    /// The network type, representing either TCP or UDP.
    pub network: Network,
    /// The socket address of the remote peer of an inbound connection.
    pub source: SocketAddr,
    /// The socket address of the local socket of an inbound connection.
    pub local_addr: SocketAddr,
    /// The proxy target address of a proxy connection.
    pub destination: SocksAddr,
    /// The tag of the inbound handler this session initiated.
    pub inbound_tag: String,
    /// The tag of the first outbound handler this session goes.
    pub outbound_tag: String,
    /// Whether the session is being carried through a chain. What carries it
    /// there is what the chain hands the actor that runs, not an endpoint the
    /// actor dials for itself.
    pub in_chain: bool,
    /// Optional stream ID for multiplexing transports.
    pub stream_id: Option<StreamId>,
    /// Optional source address which is forwarded via HTTP reverse proxy.
    pub forwarded_source: Option<IpAddr>,
    /// Optional process name that initiated this connection.
    pub process_name: Option<String>,
    /// Requires a multiplexed transport to create a new underlying connection
    /// for this session and use it only once.
    pub new_conn_once: bool,
    /// The sniffed domain name from TLS SNI.
    pub tls_sniffed_domain: Option<String>,
    /// The sniffed domain name from HTTP Host.
    pub http_sniffed_domain: Option<String>,
    /// The sniffed domain name if the destination is an IP address.
    pub dns_sniffed_domain: Option<String>,
    /// The server name of the outer TLS or REALITY connection, available as
    /// soon as the inbound transport is established. Used by the VLESS
    /// fallbacks, which must select before any payload has been sniffed.
    pub outer_sni: Option<String>,
    /// The ALPN protocol negotiated on the outer TLS or REALITY connection.
    pub outer_alpn: Option<String>,
    /// Shared state to coordinate XTLS vision read raw mode.
    pub vision_read_raw: std::sync::Arc<std::sync::atomic::AtomicBool>,
    /// Skip domain resolution during routing.
    pub skip_resolve: bool,
}

impl Clone for Session {
    fn clone(&self) -> Self {
        Session {
            span: self.span.clone(),
            network: self.network,
            source: self.source,
            local_addr: self.local_addr,
            destination: self.destination.clone(),
            inbound_tag: self.inbound_tag.clone(),
            outbound_tag: self.outbound_tag.clone(),
            in_chain: self.in_chain,
            stream_id: self.stream_id,
            forwarded_source: self.forwarded_source,
            process_name: self.process_name.clone(),
            new_conn_once: self.new_conn_once,
            tls_sniffed_domain: self.tls_sniffed_domain.clone(),
            http_sniffed_domain: self.http_sniffed_domain.clone(),
            dns_sniffed_domain: self.dns_sniffed_domain.clone(),
            outer_sni: self.outer_sni.clone(),
            outer_alpn: self.outer_alpn.clone(),
            vision_read_raw: self.vision_read_raw.clone(),
            skip_resolve: self.skip_resolve,
        }
    }
}

impl Default for Session {
    fn default() -> Self {
        Session {
            span: Self::create_span(),
            network: Network::Tcp,
            source: *crate::option::UNSPECIFIED_BIND_ADDR,
            local_addr: *crate::option::UNSPECIFIED_BIND_ADDR,
            destination: SocksAddr::any(),
            inbound_tag: "".to_string(),
            outbound_tag: "".to_string(),
            in_chain: false,
            stream_id: None,
            forwarded_source: None,
            process_name: None,
            new_conn_once: false,
            tls_sniffed_domain: None,
            http_sniffed_domain: None,
            dns_sniffed_domain: None,
            outer_sni: None,
            outer_alpn: None,
            vision_read_raw: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
            skip_resolve: false,
        }
    }
}

impl Session {
    pub fn create_span() -> tracing::Span {
        use rand::Rng;
        let mut rng = rand::thread_rng();
        let trace_id: String = (0..8)
            .map(|_| {
                const CHARS: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";
                let idx = rng.gen_range(0..CHARS.len());
                CHARS[idx] as char
            })
            .collect();
        let span = tracing::debug_span!("sess", tid = trace_id);
        let _g = span.enter();
        tracing::debug!("created span");
        span.clone()
    }

    pub fn new_span(&mut self) {
        self.span = Self::create_span();
    }

    pub fn span(&self) -> tracing::Span {
        self.span.clone()
    }

    pub fn destination_for_routing(&self) -> io::Result<Cow<'_, SocksAddr>> {
        let mut target_domain = None;
        if crate::option::TLS_DOMAIN_SNIFFING.load(std::sync::atomic::Ordering::Relaxed) {
            if let Some(domain) = &self.tls_sniffed_domain {
                target_domain = Some(domain);
            }
        }
        if target_domain.is_none()
            && crate::option::HTTP_DOMAIN_SNIFFING.load(std::sync::atomic::Ordering::Relaxed)
        {
            if let Some(domain) = &self.http_sniffed_domain {
                target_domain = Some(domain);
            }
        }
        if target_domain.is_none()
            && crate::option::DNS_DOMAIN_SNIFFING.load(std::sync::atomic::Ordering::Relaxed)
        {
            if let Some(domain) = &self.dns_sniffed_domain {
                target_domain = Some(domain);
            }
        }

        if let Some(domain) = target_domain {
            Ok(Cow::Owned(SocksAddr::try_from((
                domain.as_str(),
                self.destination.port(),
            ))?))
        } else {
            Ok(Cow::Borrowed(&self.destination))
        }
    }
}

struct SocksAddrPortLastType;

impl SocksAddrPortLastType {
    const V4: u8 = 0x1;
    const V6: u8 = 0x4;
    const DOMAIN: u8 = 0x3;
}

struct SocksAddrPortFirstType;

impl SocksAddrPortFirstType {
    const V4: u8 = 0x1;
    const V6: u8 = 0x3;
    const DOMAIN: u8 = 0x2;
}

#[derive(Clone, Copy)]
pub enum SocksAddrWireType {
    PortFirst,
    PortLast,
}

#[derive(Debug, PartialEq, Eq)]
pub enum SocksAddr {
    Ip(SocketAddr),
    Domain(String, u16),
}

fn insuff_bytes() -> io::Error {
    io::Error::other("insufficient bytes")
}

fn invalid_addr_type() -> io::Error {
    io::Error::other("invalid address type")
}

impl SocksAddr {
    pub fn any() -> Self {
        Self::Ip(*crate::option::UNSPECIFIED_BIND_ADDR)
    }

    pub fn any_ipv4() -> Self {
        Self::Ip("0.0.0.0:0".parse().unwrap())
    }

    pub fn any_ipv6() -> Self {
        Self::Ip("[::]:0".parse().unwrap())
    }

    pub fn must_ip(&self) -> &SocketAddr {
        match self {
            SocksAddr::Ip(ref a) => a,
            _ => {
                panic!("assert SocksAddr as SocketAddr failed");
            }
        }
    }

    pub fn size(&self) -> usize {
        match self {
            Self::Ip(addr) => match addr {
                SocketAddr::V4(_addr) => 1 + 4 + 2,
                SocketAddr::V6(_addr) => 1 + 16 + 2,
            },
            Self::Domain(domain, _port) => 1 + 1 + domain.len() + 2,
        }
    }

    pub fn port(&self) -> u16 {
        match self {
            SocksAddr::Ip(addr) => addr.port(),
            SocksAddr::Domain(_, port) => *port,
        }
    }

    pub fn is_domain(&self) -> bool {
        match self {
            SocksAddr::Ip(_) => false,
            SocksAddr::Domain(_, _) => true,
        }
    }

    pub fn domain(&self) -> Option<&String> {
        if let SocksAddr::Domain(ref domain, _) = self {
            Some(domain)
        } else {
            None
        }
    }

    pub fn ip(&self) -> Option<IpAddr> {
        if let SocksAddr::Ip(addr) = self {
            Some(addr.ip())
        } else {
            None
        }
    }

    pub fn host(&self) -> String {
        match self {
            SocksAddr::Ip(addr) => {
                let ip = addr.ip();
                ip.to_string()
            }
            SocksAddr::Domain(domain, _) => domain.to_owned(),
        }
    }

    /// Writes `self` into `buf`.
    pub fn write_buf<T: BufMut>(&self, buf: &mut T, addr_type: SocksAddrWireType) {
        match self {
            Self::Ip(addr) => match addr {
                SocketAddr::V4(addr) => match addr_type {
                    SocksAddrWireType::PortLast => {
                        buf.put_u8(SocksAddrPortLastType::V4);
                        buf.put_slice(&addr.ip().octets());
                        buf.put_u16(addr.port());
                    }
                    SocksAddrWireType::PortFirst => {
                        buf.put_u16(addr.port());
                        buf.put_u8(SocksAddrPortFirstType::V4);
                        buf.put_slice(&addr.ip().octets());
                    }
                },
                SocketAddr::V6(addr) => match addr_type {
                    SocksAddrWireType::PortLast => {
                        buf.put_u8(SocksAddrPortLastType::V6);
                        buf.put_slice(&addr.ip().octets());
                        buf.put_u16(addr.port());
                    }
                    SocksAddrWireType::PortFirst => {
                        buf.put_u16(addr.port());
                        buf.put_u8(SocksAddrPortFirstType::V6);
                        buf.put_slice(&addr.ip().octets());
                    }
                },
            },
            Self::Domain(domain, port) => match addr_type {
                SocksAddrWireType::PortLast => {
                    buf.put_u8(SocksAddrPortLastType::DOMAIN);
                    buf.put_u8(domain.len() as u8);
                    buf.put_slice(domain.as_bytes());
                    buf.put_u16(*port);
                }
                SocksAddrWireType::PortFirst => {
                    buf.put_u16(*port);
                    buf.put_u8(SocksAddrPortFirstType::DOMAIN);
                    buf.put_u8(domain.len() as u8);
                    buf.put_slice(domain.as_bytes());
                }
            },
        }
    }

    pub async fn read_from<T: AsyncRead + Unpin>(
        r: &mut T,
        addr_type: SocksAddrWireType,
    ) -> io::Result<Self> {
        // Read the fixed-size head, then size the rest of the frame from its
        // own length fields, and hand the whole thing to the slice parser so
        // there is only one wire codec.
        let mut buf = match addr_type {
            // [type, ...]
            SocksAddrWireType::PortLast => vec![r.read_u8().await?],
            // [port hi, port lo, type, ...]
            SocksAddrWireType::PortFirst => {
                let mut head = [0u8; 3];
                r.read_exact(&mut head).await?;
                head.to_vec()
            }
        };
        let remaining = match addr_type {
            SocksAddrWireType::PortLast => match buf[0] {
                SocksAddrPortLastType::V4 => 4 + 2,
                SocksAddrPortLastType::V6 => 16 + 2,
                SocksAddrPortLastType::DOMAIN => {
                    buf.push(r.read_u8().await?);
                    buf[1] as usize + 2
                }
                _ => return Err(invalid_addr_type()),
            },
            SocksAddrWireType::PortFirst => match buf[2] {
                SocksAddrPortFirstType::V4 => 4,
                SocksAddrPortFirstType::V6 => 16,
                SocksAddrPortFirstType::DOMAIN => {
                    buf.push(r.read_u8().await?);
                    buf[3] as usize
                }
                _ => return Err(invalid_addr_type()),
            },
        };
        let start = buf.len();
        buf.resize(start + remaining, 0);
        r.read_exact(&mut buf[start..]).await?;
        Self::try_from((buf.as_slice(), addr_type))
    }
}

impl Clone for SocksAddr {
    fn clone(&self) -> Self {
        match self {
            SocksAddr::Ip(a) => Self::from(a.to_owned()),
            SocksAddr::Domain(domain, port) => match domain.parse::<IpAddr>() {
                Ok(ip) => Self::Ip(SocketAddr::new(ip, *port)),
                Err(_) => Self::Domain(domain.clone(), *port),
            },
        }
    }
}

impl fmt::Display for SocksAddr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let s = match self {
            SocksAddr::Ip(addr) => addr.to_string(),
            SocksAddr::Domain(domain, port) => format!("{}:{}", domain, port),
        };
        write!(f, "{}", s)
    }
}

impl From<(IpAddr, u16)> for SocksAddr {
    fn from(value: (IpAddr, u16)) -> Self {
        Self::Ip(value.into())
    }
}

impl From<(Ipv4Addr, u16)> for SocksAddr {
    fn from(value: (Ipv4Addr, u16)) -> Self {
        Self::Ip(value.into())
    }
}

impl From<(Ipv6Addr, u16)> for SocksAddr {
    fn from(value: (Ipv6Addr, u16)) -> Self {
        Self::Ip(value.into())
    }
}

impl From<SocketAddr> for SocksAddr {
    fn from(value: SocketAddr) -> Self {
        Self::Ip(value)
    }
}

impl From<&SocketAddr> for SocksAddr {
    fn from(addr: &SocketAddr) -> Self {
        Self::Ip(addr.to_owned())
    }
}

impl From<SocketAddrV4> for SocksAddr {
    fn from(value: SocketAddrV4) -> Self {
        Self::Ip(value.into())
    }
}

impl From<SocketAddrV6> for SocksAddr {
    fn from(value: SocketAddrV6) -> Self {
        Self::Ip(value.into())
    }
}

impl TryFrom<(&str, u16)> for SocksAddr {
    type Error = io::Error;

    fn try_from((addr, port): (&str, u16)) -> Result<Self, Self::Error> {
        Self::try_from((addr.to_string(), port))
    }
}

impl TryFrom<(&String, u16)> for SocksAddr {
    type Error = io::Error;

    fn try_from((addr, port): (&String, u16)) -> Result<Self, Self::Error> {
        Self::try_from((addr.to_owned(), port))
    }
}

impl TryFrom<(String, u16)> for SocksAddr {
    type Error = io::Error;

    fn try_from((addr, port): (String, u16)) -> Result<Self, Self::Error> {
        if let Ok(ip) = addr.parse::<IpAddr>() {
            return Ok(Self::from((ip, port)));
        }
        if addr.len() > 0xff {
            return Err(io::Error::other("domain too long"));
        }
        Ok(Self::Domain(addr, port))
    }
}

/// Tries to read `SocksAddr` from `&[u8]`.
impl TryFrom<(&[u8], SocksAddrWireType)> for SocksAddr {
    type Error = io::Error;

    fn try_from((buf, addr_type): (&[u8], SocksAddrWireType)) -> Result<Self, Self::Error> {
        if buf.is_empty() {
            return Err(insuff_bytes());
        }

        match addr_type {
            SocksAddrWireType::PortLast => match buf[0] {
                SocksAddrPortLastType::V4 => {
                    if buf.len() < 1 + 4 + 2 {
                        return Err(insuff_bytes());
                    }
                    let mut ip_bytes = [0u8; 4];
                    ip_bytes.copy_from_slice(&buf[1..5]);
                    let ip = Ipv4Addr::from(ip_bytes);
                    let mut port_bytes = [0u8; 2];
                    port_bytes.copy_from_slice(&buf[5..7]);
                    let port = u16::from_be_bytes(port_bytes);
                    Ok(Self::Ip((ip, port).into()))
                }
                SocksAddrPortLastType::V6 => {
                    if buf.len() < 1 + 16 + 2 {
                        return Err(insuff_bytes());
                    }
                    let mut ip_bytes = [0u8; 16];
                    ip_bytes.copy_from_slice(&buf[1..17]);
                    let ip = Ipv6Addr::from(ip_bytes);
                    let mut port_bytes = [0u8; 2];
                    port_bytes.copy_from_slice(&buf[17..19]);
                    let port = u16::from_be_bytes(port_bytes);
                    Ok(Self::Ip((ip, port).into()))
                }
                SocksAddrPortLastType::DOMAIN => {
                    if buf.len() < 2 {
                        return Err(insuff_bytes());
                    }
                    let domain_len = buf[1] as usize;
                    if buf.len() < 2 + domain_len + 2 {
                        return Err(insuff_bytes());
                    }
                    let domain = String::from_utf8(buf[2..domain_len + 2].to_vec())
                        .map_err(|e| io::Error::other(format!("invalid domain: {}", e)))?;
                    let mut port_bytes = [0u8; 2];
                    port_bytes.copy_from_slice(&buf[domain_len + 2..domain_len + 4]);
                    let port = u16::from_be_bytes(port_bytes);
                    Ok(Self::Domain(domain, port))
                }
                _ => Err(io::Error::other("invalid address type")),
            },
            // [port hi, port lo, type, payload...]
            SocksAddrWireType::PortFirst => {
                if buf.len() < 3 {
                    return Err(insuff_bytes());
                }
                let port = u16::from_be_bytes([buf[0], buf[1]]);
                let payload = &buf[3..];
                match buf[2] {
                    SocksAddrPortFirstType::V4 => {
                        if payload.len() < 4 {
                            return Err(insuff_bytes());
                        }
                        let mut ip_bytes = [0u8; 4];
                        ip_bytes.copy_from_slice(&payload[..4]);
                        let ip = Ipv4Addr::from(ip_bytes);
                        Ok(Self::Ip((ip, port).into()))
                    }
                    SocksAddrPortFirstType::V6 => {
                        if payload.len() < 16 {
                            return Err(insuff_bytes());
                        }
                        let mut ip_bytes = [0u8; 16];
                        ip_bytes.copy_from_slice(&payload[..16]);
                        let ip = Ipv6Addr::from(ip_bytes);
                        Ok(Self::Ip((ip, port).into()))
                    }
                    SocksAddrPortFirstType::DOMAIN => {
                        if payload.len() < 1 {
                            return Err(insuff_bytes());
                        }
                        let domain_len = payload[0] as usize;
                        if payload.len() < 1 + domain_len {
                            return Err(insuff_bytes());
                        }
                        let domain = String::from_utf8(payload[1..1 + domain_len].to_vec())
                            .map_err(|e| io::Error::other(format!("invalid domain: {}", e)))?;
                        Ok(Self::Domain(domain, port))
                    }
                    _ => Err(io::Error::other("invalid address type")),
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn runtime() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
    }

    fn test_addrs() -> Vec<SocksAddr> {
        vec![
            SocksAddr::Ip("127.0.0.1:8080".parse().unwrap()),
            SocksAddr::Ip("[2001:db8::1]:8080".parse().unwrap()),
            SocksAddr::Domain("example.com".to_string(), 443),
        ]
    }

    fn label(wire: &SocksAddrWireType) -> &'static str {
        match wire {
            SocksAddrWireType::PortFirst => "port-first",
            SocksAddrWireType::PortLast => "port-last",
        }
    }

    fn encode(addr: &SocksAddr, wire: SocksAddrWireType) -> Vec<u8> {
        let mut buf = Vec::new();
        addr.write_buf(&mut buf, wire);
        buf
    }

    #[test]
    fn write_buf_round_trips_through_slice_parser() {
        for wire in [SocksAddrWireType::PortFirst, SocksAddrWireType::PortLast] {
            for addr in test_addrs() {
                let buf = encode(&addr, wire);
                assert_eq!(buf.len(), addr.size(), "{} {:?}", label(&wire), addr);
                let parsed = SocksAddr::try_from((buf.as_slice(), wire)).unwrap();
                assert_eq!(parsed, addr, "{} {:?}", label(&wire), addr);
                if let SocksAddrWireType::PortFirst = wire {
                    // PortFirst leads with the big-endian port; the address
                    // type byte only follows it.
                    assert_eq!(buf[..2], addr.port().to_be_bytes());
                    assert_eq!(
                        buf[2],
                        match &addr {
                            SocksAddr::Ip(SocketAddr::V4(_)) => SocksAddrPortFirstType::V4,
                            SocksAddr::Ip(SocketAddr::V6(_)) => SocksAddrPortFirstType::V6,
                            SocksAddr::Domain(_, _) => SocksAddrPortFirstType::DOMAIN,
                        }
                    );
                }
            }
        }
    }

    #[test]
    fn write_buf_round_trips_through_read_from() {
        runtime().block_on(async {
            for wire in [SocksAddrWireType::PortFirst, SocksAddrWireType::PortLast] {
                for addr in test_addrs() {
                    let buf = encode(&addr, wire);
                    let mut r: &[u8] = buf.as_slice();
                    let parsed = SocksAddr::read_from(&mut r, wire).await.unwrap();
                    assert_eq!(parsed, addr, "{} {:?}", label(&wire), addr);
                }
            }
        });
    }

    #[test]
    fn truncated_frames_are_errors_not_panics() {
        runtime().block_on(async {
            for wire in [SocksAddrWireType::PortFirst, SocksAddrWireType::PortLast] {
                for addr in test_addrs() {
                    let buf = encode(&addr, wire);
                    for len in 0..buf.len() {
                        let truncated = &buf[..len];
                        assert!(
                            SocksAddr::try_from((truncated, wire)).is_err(),
                            "slice parser accepted {}-byte prefix of {} {:?}",
                            len,
                            label(&wire),
                            addr
                        );
                        let mut r: &[u8] = truncated;
                        assert!(
                            SocksAddr::read_from(&mut r, wire).await.is_err(),
                            "read_from accepted {}-byte prefix of {} {:?}",
                            len,
                            label(&wire),
                            addr
                        );
                    }
                }
            }
        });
    }
}
