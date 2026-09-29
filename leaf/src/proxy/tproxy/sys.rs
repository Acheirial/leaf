//! Socket plumbing for the TPROXY inbound.
//!
//! TPROXY is a Linux-only feature: intercepting traffic whose destination
//! address is *not* local requires the `IP_TRANSPARENT` socket option, and
//! recovering the address the client originally dialed requires the
//! `SO_ORIGINAL_DST` / `IP_RECVORIGDSTADDR` netfilter hooks. Every function in
//! this module is therefore implemented for `target_os = "linux"` and provided
//! as an [`std::io::ErrorKind::Unsupported`] stub everywhere else, so the crate
//! keeps building on macOS/Windows/BSD.
//!
//! The syscall sequence used for a listener is, in order:
//!
//! 1. `socket(AF_INET|AF_INET6, SOCK_STREAM|SOCK_DGRAM, 0)`
//! 2. `setsockopt(IPPROTO_IP, IP_TRANSPARENT, 1)` — must happen *before* bind,
//!    it is what allows the socket to own/accept a non-local destination
//! 3. `setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)` and `SO_REUSEPORT, 1`
//! 4. `bind()` then `listen()` (stream) and `fcntl(O_NONBLOCK)`
//! 5. for UDP additionally `setsockopt(IPPROTO_IP, IP_RECVORIGDSTADDR, 1)`
//!    (and `IPV6_RECVORIGDSTADDR`) so the original destination travels in the
//!    `recvmsg(2)` control message of every datagram
//!
//! and per accepted TCP connection `getsockopt(IPPROTO_IP, SO_ORIGINAL_DST)`
//! (IPv4) or `getsockopt(IPPROTO_IPV6, IP6T_SO_ORIGINAL_DST)` (IPv6) recovers
//! the destination that the client dialed.

#[cfg(target_os = "linux")]
mod imp {
    use std::io;
    use std::mem::size_of;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
    use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};

    // Levels and options that are not consistently exported by `libc` across
    // architectures; the numeric values are stable parts of the Linux UAPI.
    const IP_RECVORIGDSTADDR: libc::c_int = libc::IP_RECVORIGDSTADDR;
    const IPV6_RECVORIGDSTADDR: libc::c_int = 74;
    const IP_PKTINFO: libc::c_int = libc::IP_PKTINFO;
    const IPV6_PKTINFO: libc::c_int = 50;
    const SO_ORIGINAL_DST: libc::c_int = libc::SO_ORIGINAL_DST;
    const IP6T_SO_ORIGINAL_DST: libc::c_int = libc::IP6T_SO_ORIGINAL_DST;

    /// Returned when a receive path could not report a peer address.
    const UNSPECIFIED: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0);

    fn setsockopt_int(
        fd: RawFd,
        level: libc::c_int,
        name: libc::c_int,
        value: libc::c_int,
    ) -> io::Result<()> {
        let ret = unsafe {
            libc::setsockopt(
                fd,
                level,
                name,
                &value as *const libc::c_int as *const libc::c_void,
                size_of::<libc::c_int>() as libc::socklen_t,
            )
        };
        if ret != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    fn new_socket(addr: &SocketAddr, ty: libc::c_int) -> io::Result<RawFd> {
        let domain = match addr {
            SocketAddr::V4(_) => libc::AF_INET,
            SocketAddr::V6(_) => libc::AF_INET6,
        };
        let fd = unsafe { libc::socket(domain, ty | libc::SOCK_CLOEXEC, 0) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(fd)
    }

    /// Turns a [`SocketAddr`] into a raw `sockaddr` for `bind(2)`.
    fn to_sockaddr_storage(addr: &SocketAddr) -> (libc::sockaddr_storage, libc::socklen_t) {
        let mut storage: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
        match addr {
            SocketAddr::V4(v4) => {
                let sin = &mut storage as *mut libc::sockaddr_storage as *mut libc::sockaddr_in;
                unsafe {
                    (*sin).sin_family = libc::AF_INET as libc::sa_family_t;
                    (*sin).sin_port = v4.port().to_be();
                    (*sin).sin_addr = libc::in_addr {
                        s_addr: u32::from_ne_bytes(v4.ip().octets()),
                    };
                }
                (storage, size_of::<libc::sockaddr_in>() as libc::socklen_t)
            }
            SocketAddr::V6(v6) => {
                let sin6 = &mut storage as *mut libc::sockaddr_storage as *mut libc::sockaddr_in6;
                unsafe {
                    (*sin6).sin6_family = libc::AF_INET6 as libc::sa_family_t;
                    (*sin6).sin6_port = v6.port().to_be();
                    (*sin6).sin6_flowinfo = v6.flowinfo();
                    (*sin6).sin6_addr = libc::in6_addr {
                        s6_addr: v6.ip().octets(),
                    };
                    (*sin6).sin6_scope_id = v6.scope_id();
                }
                (storage, size_of::<libc::sockaddr_in6>() as libc::socklen_t)
            }
        }
    }

    fn bind_raw(fd: RawFd, addr: &SocketAddr) -> io::Result<()> {
        let (storage, len) = to_sockaddr_storage(addr);
        let ret = unsafe { libc::bind(fd, &storage as *const _ as *const libc::sockaddr, len) };
        if ret != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    fn listen_raw(fd: RawFd, backlog: libc::c_int) -> io::Result<()> {
        let ret = unsafe { libc::listen(fd, backlog) };
        if ret != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    fn set_nonblocking_raw(fd: RawFd) -> io::Result<()> {
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        if flags < 0 {
            return Err(io::Error::last_os_error());
        }
        let ret = unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) };
        if ret < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    /// Applies the options every transparent listener needs. Must be called
    /// *before* `bind(2)`: `IP_TRANSPARENT` is what lets the socket be
    /// associated with a destination address that is not local.
    fn configure_transparent(fd: RawFd, addr: &SocketAddr) -> io::Result<()> {
        setsockopt_int(fd, libc::IPPROTO_IP, libc::IP_TRANSPARENT, 1)?;
        if addr.is_ipv6() {
            // Best effort: some kernels reject the IPv6 flavour.
            let _ = setsockopt_int(fd, libc::IPPROTO_IPV6, libc::IPV6_TRANSPARENT, 1);
        }
        setsockopt_int(fd, libc::SOL_SOCKET, libc::SO_REUSEADDR, 1)?;
        // Best effort: needed for the per-destination spoofed reply sockets.
        let _ = setsockopt_int(fd, libc::SOL_SOCKET, libc::SO_REUSEPORT, 1);
        Ok(())
    }

    /// Mainline Linux does not export `CMSG_NXTHDR` through `libc`, so the
    /// control-message walk is done by hand. The alignment matches
    /// `_CMSG_ALIGN`, i.e. `sizeof(long)`.
    fn cmsg_align(len: usize) -> usize {
        let align = size_of::<usize>();
        (len + align - 1) & !(align - 1)
    }

    /// `CMSG_LEN(0)`: the smallest a control-message record can be — the
    /// aligned size of the header carrying no payload.
    fn cmsg_len_0() -> usize {
        cmsg_align(size_of::<libc::cmsghdr>())
    }

    unsafe fn sockaddr_in_to_socketaddr(sin: &libc::sockaddr_in) -> Option<SocketAddr> {
        if sin.sin_family as libc::c_int != libc::AF_INET {
            return None;
        }
        let ip = Ipv4Addr::from(sin.sin_addr.s_addr.to_ne_bytes());
        Some(SocketAddr::new(IpAddr::V4(ip), u16::from_be(sin.sin_port)))
    }

    unsafe fn sockaddr_in6_to_socketaddr(sin6: &libc::sockaddr_in6) -> Option<SocketAddr> {
        if sin6.sin6_family as libc::c_int != libc::AF_INET6 {
            return None;
        }
        let port = u16::from_be(sin6.sin6_port);
        let ip = Ipv6Addr::from(sin6.sin6_addr.s6_addr);
        // A v4-mapped address (::ffff:a.b.c.d) is an IPv4 destination.
        if let Some(v4) = ip.to_ipv4_mapped() {
            return Some(SocketAddr::new(IpAddr::V4(v4), port));
        }
        Some(SocketAddr::new(IpAddr::V6(ip), port))
    }

    unsafe fn sockaddr_storage_to_socketaddr(ss: &libc::sockaddr_storage) -> Option<SocketAddr> {
        match ss.ss_family as libc::c_int {
            libc::AF_INET => {
                sockaddr_in_to_socketaddr(&*(ss as *const _ as *const libc::sockaddr_in))
            }
            libc::AF_INET6 => {
                sockaddr_in6_to_socketaddr(&*(ss as *const _ as *const libc::sockaddr_in6))
            }
            _ => None,
        }
    }

    fn socket_family(fd: RawFd) -> io::Result<libc::c_int> {
        let mut ss: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
        let mut len = size_of::<libc::sockaddr_storage>() as libc::socklen_t;
        let ret =
            unsafe { libc::getsockname(fd, &mut ss as *mut _ as *mut libc::sockaddr, &mut len) };
        if ret != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(ss.ss_family as libc::c_int)
    }

    fn enable_recv_orig_dst_fd(fd: RawFd) -> io::Result<()> {
        let v4 = setsockopt_int(fd, libc::IPPROTO_IP, IP_RECVORIGDSTADDR, 1);
        let v6 = setsockopt_int(fd, libc::IPPROTO_IPV6, IPV6_RECVORIGDSTADDR, 1);
        match (v4, v6) {
            // Neither address family accepted the option: the platform cannot
            // report the original destination at all.
            (Err(e4), Err(_)) => {
                return Err(io::Error::new(
                    e4.kind(),
                    format!("cannot enable IP_RECVORIGDSTADDR: {}", e4),
                ));
            }
            _ => {}
        }
        // Best effort: `IP_PKTINFO` gives a fallback when the original
        // destination is absent (e.g. non-transparent traffic).
        let _ = setsockopt_int(fd, libc::IPPROTO_IP, IP_PKTINFO, 1);
        let _ = setsockopt_int(fd, libc::IPPROTO_IPV6, IPV6_PKTINFO, 1);
        Ok(())
    }

    /// Creates a TCP listening socket with `IP_TRANSPARENT` set before bind,
    /// then `listen(2)` and non-blocking mode. See the module docs for the
    /// exact syscall order.
    pub fn tcp_listener(addr: &SocketAddr) -> io::Result<tokio::net::TcpListener> {
        let fd = new_socket(addr, libc::SOCK_STREAM)?;
        if let Err(e) = configure_transparent(fd, addr)
            .and_then(|_| bind_raw(fd, addr))
            .and_then(|_| listen_raw(fd, 1024))
            .and_then(|_| set_nonblocking_raw(fd))
        {
            unsafe { libc::close(fd) };
            return Err(e);
        }
        let std_listener = unsafe { std::net::TcpListener::from_raw_fd(fd) };
        tokio::net::TcpListener::from_std(std_listener)
    }

    /// Creates a UDP socket with `IP_TRANSPARENT`, `IP_RECVORIGDSTADDR` and
    /// `IP_PKTINFO` set, bound to `addr` and switched to non-blocking mode.
    pub fn udp_socket(addr: &SocketAddr) -> io::Result<tokio::net::UdpSocket> {
        let fd = new_socket(addr, libc::SOCK_DGRAM)?;
        if let Err(e) = configure_transparent(fd, addr)
            .and_then(|_| enable_recv_orig_dst_fd(fd))
            .and_then(|_| bind_raw(fd, addr))
            .and_then(|_| set_nonblocking_raw(fd))
        {
            unsafe { libc::close(fd) };
            return Err(e);
        }
        let std_socket = unsafe { std::net::UdpSocket::from_raw_fd(fd) };
        tokio::net::UdpSocket::from_std(std_socket)
    }

    /// Sets `IP_TRANSPARENT` on an already created socket.
    pub fn set_transparent<S: AsRawFd>(sock: &S) -> io::Result<()> {
        setsockopt_int(sock.as_raw_fd(), libc::IPPROTO_IP, libc::IP_TRANSPARENT, 1)
    }

    /// Enables per-datagram original-destination reporting on a UDP socket.
    pub fn enable_recv_orig_dst<S: AsRawFd>(sock: &S) -> io::Result<()> {
        enable_recv_orig_dst_fd(sock.as_raw_fd())
    }

    /// Recovers the destination the client originally dialed, via
    /// `getsockopt(SO_ORIGINAL_DST)` for IPv4 and
    /// `getsockopt(IP6T_SO_ORIGINAL_DST)` for IPv6. This is the REDIRECT-mode
    /// recovery; in TPROXY mode the same address is also reported as the
    /// accepted socket's local address.
    pub fn original_dst<S: AsRawFd>(sock: &S) -> io::Result<SocketAddr> {
        original_dst_fd(sock.as_raw_fd())
    }

    /// [`original_dst`] for a raw file descriptor.
    pub fn original_dst_fd(fd: RawFd) -> io::Result<SocketAddr> {
        let family = socket_family(fd)?;
        if family == libc::AF_INET6 {
            let mut sin6: libc::sockaddr_in6 = unsafe { std::mem::zeroed() };
            let mut len = size_of::<libc::sockaddr_in6>() as libc::socklen_t;
            let ret = unsafe {
                libc::getsockopt(
                    fd,
                    libc::IPPROTO_IPV6,
                    IP6T_SO_ORIGINAL_DST,
                    &mut sin6 as *mut _ as *mut libc::c_void,
                    &mut len,
                )
            };
            if ret != 0 {
                return Err(io::Error::last_os_error());
            }
            unsafe { sockaddr_in6_to_socketaddr(&sin6) }.ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "IP6T_SO_ORIGINAL_DST returned no address",
                )
            })
        } else {
            let mut sin: libc::sockaddr_in = unsafe { std::mem::zeroed() };
            let mut len = size_of::<libc::sockaddr_in>() as libc::socklen_t;
            let ret = unsafe {
                libc::getsockopt(
                    fd,
                    libc::IPPROTO_IP,
                    SO_ORIGINAL_DST,
                    &mut sin as *mut _ as *mut libc::c_void,
                    &mut len,
                )
            };
            if ret != 0 {
                return Err(io::Error::last_os_error());
            }
            unsafe { sockaddr_in_to_socketaddr(&sin) }.ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "SO_ORIGINAL_DST returned no address",
                )
            })
        }
    }

    /// `recvmsg(2)` wrapper that returns `(len, peer, original_destination)`.
    ///
    /// The original destination is read from the `IP_RECVORIGDSTADDR` /
    /// `IPV6_RECVORIGDSTADDR` control message; when it is absent the local
    /// address from `IP_PKTINFO` is used, and failing that the peer address.
    /// The returned error is `WouldBlock` when the socket has no data; the
    /// caller drives this from tokio's `async_io`, which awaits readiness and
    /// retries on `WouldBlock` rather than surfacing it.
    pub fn recv_from_original_dst<S: AsRawFd>(
        sock: &S,
        buf: &mut [u8],
    ) -> io::Result<(usize, SocketAddr, SocketAddr)> {
        recv_from_original_dst_fd(sock.as_raw_fd(), buf)
    }

    /// [`recv_from_original_dst`] for a raw file descriptor.
    pub fn recv_from_original_dst_fd(
        fd: RawFd,
        buf: &mut [u8],
    ) -> io::Result<(usize, SocketAddr, SocketAddr)> {
        #[repr(align(8))]
        struct ControlBuffer([u8; 256]);

        let mut control = ControlBuffer([0u8; 256]);
        let mut ss: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
        let mut iov = libc::iovec {
            iov_base: buf.as_mut_ptr() as *mut libc::c_void,
            iov_len: buf.len(),
        };
        let mut mhdr: libc::msghdr = unsafe { std::mem::zeroed() };
        mhdr.msg_name = &mut ss as *mut _ as *mut libc::c_void;
        mhdr.msg_namelen = size_of::<libc::sockaddr_storage>() as libc::socklen_t;
        mhdr.msg_iov = &mut iov;
        mhdr.msg_iovlen = 1;
        mhdr.msg_control = control.0.as_mut_ptr() as *mut libc::c_void;
        mhdr.msg_controllen = control.0.len() as _;

        let n = unsafe { libc::recvmsg(fd, &mut mhdr, 0) };
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        let n = n as usize;

        let peer = unsafe { sockaddr_storage_to_socketaddr(&ss) };

        let mut original: Option<SocketAddr> = None;
        let mut local: Option<SocketAddr> = None;
        let base = mhdr.msg_control as *const u8;
        let used = mhdr.msg_controllen as usize;
        let mut offset = 0usize;
        while offset + size_of::<libc::cmsghdr>() <= used {
            let cmsg = unsafe { base.add(offset) as *const libc::cmsghdr };
            let cmsg_len = unsafe { (*cmsg).cmsg_len } as usize;
            // Reject a malformed/truncated control buffer: the record must be at
            // least `CMSG_LEN(0)` long and must fit inside the bytes the kernel
            // reported as used. Stop the walk rather than reading out of bounds.
            if cmsg_len < cmsg_len_0() || cmsg_len > used - offset {
                break;
            }
            let level = unsafe { (*cmsg).cmsg_level };
            let ctype = unsafe { (*cmsg).cmsg_type };
            let data = unsafe { base.add(offset + size_of::<libc::cmsghdr>()) };
            if level == libc::IPPROTO_IP && ctype == IP_RECVORIGDSTADDR {
                original =
                    unsafe { sockaddr_in_to_socketaddr(&*(data as *const libc::sockaddr_in)) };
            } else if level == libc::IPPROTO_IPV6 && ctype == IPV6_RECVORIGDSTADDR {
                original =
                    unsafe { sockaddr_in6_to_socketaddr(&*(data as *const libc::sockaddr_in6)) };
            } else if level == libc::IPPROTO_IP && ctype == IP_PKTINFO {
                // struct in_pktinfo { int ipi_ifindex; struct in_addr ipi_spec_dst; struct in_addr ipi_addr; }
                let mut octets = [0u8; 4];
                unsafe { std::ptr::copy_nonoverlapping(data.add(8), octets.as_mut_ptr(), 4) };
                local = Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::from(octets)), 0));
            } else if level == libc::IPPROTO_IPV6 && ctype == IPV6_PKTINFO {
                // struct in6_pktinfo { struct in6_addr ipi6_addr; unsigned int ipi6_ifindex; }
                let mut octets = [0u8; 16];
                unsafe { std::ptr::copy_nonoverlapping(data, octets.as_mut_ptr(), 16) };
                local = Some(SocketAddr::new(IpAddr::V6(Ipv6Addr::from(octets)), 0));
            }
            offset += cmsg_align(cmsg_len);
        }

        let peer = peer.unwrap_or(UNSPECIFIED);
        let dst = original.or(local).unwrap_or(peer);
        Ok((n, peer, dst))
    }

    /// Creates a UDP socket that can *send from* `src`, even when `src` is not
    /// a local address. This is the TPROXY reply trick: the kernel forwarded
    /// the client's packet with its destination untouched, so the reply must
    /// leave from that same destination address to be accepted by the client.
    ///
    /// Sequence: `socket(AF_INET|AF_INET6, SOCK_DGRAM)` →
    /// `setsockopt(IP_TRANSPARENT)` → `SO_REUSEADDR` → `SO_REUSEPORT` →
    /// `bind(src)` → non-blocking.
    pub fn bind_spoofed_udp(src: &SocketAddr) -> io::Result<tokio::net::UdpSocket> {
        let fd = new_socket(src, libc::SOCK_DGRAM)?;
        if let Err(e) = configure_transparent(fd, src)
            .and_then(|_| bind_raw(fd, src))
            .and_then(|_| set_nonblocking_raw(fd))
        {
            unsafe { libc::close(fd) };
            return Err(e);
        }
        let std_socket = unsafe { std::net::UdpSocket::from_raw_fd(fd) };
        tokio::net::UdpSocket::from_std(std_socket)
    }

    /// Whether the running platform implements TPROXY. Always `true` here.
    pub fn is_supported() -> bool {
        true
    }
}

#[cfg(not(target_os = "linux"))]
mod imp {
    use std::io;
    use std::net::SocketAddr;

    fn unsupported<T>() -> io::Result<T> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "TPROXY is only supported on Linux",
        ))
    }

    pub fn tcp_listener(_addr: &SocketAddr) -> io::Result<tokio::net::TcpListener> {
        unsupported()
    }

    pub fn udp_socket(_addr: &SocketAddr) -> io::Result<tokio::net::UdpSocket> {
        unsupported()
    }

    pub fn set_transparent<S>(_sock: &S) -> io::Result<()> {
        unsupported()
    }

    pub fn enable_recv_orig_dst<S>(_sock: &S) -> io::Result<()> {
        unsupported()
    }

    pub fn original_dst<S>(_sock: &S) -> io::Result<SocketAddr> {
        unsupported()
    }

    pub fn recv_from_original_dst<S>(
        _sock: &S,
        _buf: &mut [u8],
    ) -> io::Result<(usize, SocketAddr, SocketAddr)> {
        unsupported()
    }

    pub fn bind_spoofed_udp(_src: &SocketAddr) -> io::Result<tokio::net::UdpSocket> {
        unsupported()
    }

    pub fn is_supported() -> bool {
        false
    }
}

pub use imp::*;
