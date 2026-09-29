//! Inbound handlers of the Linux TPROXY inbound.

mod datagram;
mod stream;

pub use datagram::Handler as DatagramHandler;
pub use stream::Handler as StreamHandler;

use std::{io, sync::Arc};

use crate::config::TproxyInboundSettings;
use crate::proxy::*;

/// The TPROXY inbound handler.
///
/// It groups the transparent TCP and UDP sub-handlers; the actual listening
/// sockets are created by `crate::app::inbound::tproxy_listener`, which is the
/// only place that can set `IP_TRANSPARENT` before `bind(2)`.
pub struct Handler {
    tag: String,
    stream: io::Result<AnyInboundStreamHandler>,
    datagram: io::Result<AnyInboundDatagramHandler>,
}

impl Handler {
    /// Builds the handler from the (currently empty) inbound settings and the
    /// inbound tag. On non-Linux platforms both sub-handlers report
    /// [`io::ErrorKind::Unsupported`], so no listener is started.
    pub fn new(_settings: &TproxyInboundSettings, tag: &str) -> Self {
        Handler {
            tag: tag.to_string(),
            stream: StreamHandler::new().map(|h| Arc::new(h) as AnyInboundStreamHandler),
            datagram: DatagramHandler::new().map(|h| Arc::new(h) as AnyInboundDatagramHandler),
        }
    }
}

impl Tag for Handler {
    fn tag(&self) -> &String {
        &self.tag
    }
}

impl BaseHandler for Handler {}

impl InboundHandler for Handler {
    fn stream(&self) -> io::Result<&AnyInboundStreamHandler> {
        self.stream
            .as_ref()
            .map_err(|e| io::Error::new(e.kind(), e.to_string()))
    }

    fn datagram(&self) -> io::Result<&AnyInboundDatagramHandler> {
        self.datagram
            .as_ref()
            .map_err(|e| io::Error::new(e.kind(), e.to_string()))
    }
}
