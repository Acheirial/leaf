use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Result;
use tracing::{debug, info, warn};

use crate::app::dispatcher::Dispatcher;
use crate::app::nat_manager::NatManager;
use crate::proxy::tproxy::sys;
use crate::proxy::AnyInboundHandler;
use crate::session::SocksAddr;
use crate::Runner;

use super::network_listener::{handle_inbound_tcp_stream, handle_udp_listen_socket};

/// Inbound listener for the Linux `TPROXY` inbound.
///
/// Unlike [`super::network_listener::NetworkInboundListener`], the listening
/// sockets are created here: `IP_TRANSPARENT` has to be set *before* `bind(2)`
/// for the kernel to deliver traffic whose destination is not local, which the
/// generic listener cannot do. Two runners are produced, one for TCP and one
/// for UDP; both reuse the generic dispatch paths so their behaviour (logging,
/// timeouts, NAT session handling) stays identical to every other inbound.
pub struct TproxyInboundListener {
    pub handler: AnyInboundHandler,
    pub dispatcher: Arc<Dispatcher>,
    pub nat_manager: Arc<NatManager>,
    pub tcp_addr: SocketAddr,
    pub udp_addr: SocketAddr,
}

impl TproxyInboundListener {
    pub fn listen(&self) -> Result<Vec<Runner>> {
        // Fail fast on platforms that cannot do TPROXY at all: the sub-handlers
        // report `io::ErrorKind::Unsupported` there.
        self.handler.stream()?;
        self.handler.datagram()?;

        let mut runners: Vec<Runner> = Vec::new();

        let handler = self.handler.clone();
        let dispatcher = self.dispatcher.clone();
        let nat_manager = self.nat_manager.clone();
        let tcp_addr = self.tcp_addr;
        runners.push(Box::pin(async move {
            if let Err(e) = handle_tcp(tcp_addr, handler, dispatcher, nat_manager).await {
                warn!("tproxy tcp listen failed: {}", e);
            }
        }));

        let handler = self.handler.clone();
        let dispatcher = self.dispatcher.clone();
        let nat_manager = self.nat_manager.clone();
        let udp_addr = self.udp_addr;
        runners.push(Box::pin(async move {
            if let Err(e) = handle_udp(udp_addr, handler, dispatcher, nat_manager).await {
                warn!("tproxy udp listen failed: {}", e);
            }
        }));

        Ok(runners)
    }
}

async fn handle_tcp(
    addr: SocketAddr,
    handler: AnyInboundHandler,
    dispatcher: Arc<Dispatcher>,
    nat_manager: Arc<NatManager>,
) -> std::io::Result<()> {
    let listener = sys::tcp_listener(&addr)?;
    let local_addr = listener.local_addr()?;
    info!("listening tcp {}", &local_addr);

    loop {
        let (stream, peer) = listener.accept().await?;

        // The address the client originally dialed. In TPROXY mode this is the
        // accepted socket's local address; `SO_ORIGINAL_DST` also covers the
        // REDIRECT-based variant, where the kernel rewrote the destination.
        let destination = match sys::original_dst(&stream) {
            Ok(destination) if !destination.ip().is_unspecified() => destination,
            Ok(_) => {
                debug!(
                    "tproxy: SO_ORIGINAL_DST returned an unspecified address, \
                     using the socket's local address"
                );
                stream.local_addr()?
            }
            Err(e) => {
                debug!(
                    "tproxy: SO_ORIGINAL_DST failed ({}), using the socket's local address",
                    e
                );
                stream.local_addr()?
            }
        };

        // The self-connection guard: proxying a connection back into this very
        // listener would loop forever. Besides loopback/unspecified
        // destinations, reject a destination that is one of the listener's own
        // bound addresses (a loopback check only covers 127.0.0.0/8, a client
        // can also reach the listener's non-loopback address) and a destination
        // equal to the connection's source address (the client dialing itself).
        if destination.ip().is_loopback()
            || destination.ip().is_unspecified()
            || destination == local_addr
            || destination == addr
            || destination == peer
        {
            debug!(
                "tproxy: dropping self-connection (destination {}, listener {}, peer {})",
                destination, local_addr, peer
            );
            continue;
        }

        let handler = handler.clone();
        let dispatcher = dispatcher.clone();
        let nat_manager = nat_manager.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_inbound_tcp_stream(
                stream,
                Some(SocksAddr::Ip(destination)),
                handler,
                dispatcher,
                nat_manager,
            )
            .await
            {
                debug!("tproxy: handle inbound stream failed: {}", e);
            }
        });
    }
}

async fn handle_udp(
    addr: SocketAddr,
    handler: AnyInboundHandler,
    dispatcher: Arc<Dispatcher>,
    nat_manager: Arc<NatManager>,
) -> std::io::Result<()> {
    let socket = sys::udp_socket(&addr)?;
    let local_addr = socket.local_addr()?;
    info!("listening udp {}", &local_addr);
    handle_udp_listen_socket(socket, handler, dispatcher, nat_manager).await
}
