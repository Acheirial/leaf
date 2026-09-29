//! The inbound half of a FinalMask transport pair.
//!
//! An inbound mask unwraps what arrived on the wire: a stream handler wraps the
//! accepted stream, a datagram handler wraps the bound socket. Both build a
//! fresh, stateful chain for every connection, in [`Role::Server`].

use std::io;

use async_trait::async_trait;

use crate::config;
use crate::proxy::*;
use crate::session::Session;

use super::datagram::MaskedInboundDatagram;
use super::masks::{self, Role, TcpMaskFactory, UdpMaskFactory};
use super::{build_tcp_factories, build_udp_factories, parse_template, FinalmaskError};

pub struct StreamHandler {
    factories: Vec<Box<dyn TcpMaskFactory>>,
}

impl StreamHandler {
    pub fn new(settings: &config::FinalmaskInboundSettings) -> Result<Self, FinalmaskError> {
        let template = parse_template(&settings.tcp_template)?;
        let factories = build_tcp_factories(&settings.tcp, template.as_ref())?;
        Ok(StreamHandler { factories })
    }
}

#[async_trait]
impl InboundStreamHandler for StreamHandler {
    async fn handle<'a>(
        &'a self,
        sess: Session,
        stream: AnyStream,
    ) -> std::io::Result<AnyInboundTransport> {
        tracing::trace!("handling inbound finalmask stream");
        let stream = masks::build_tcp(&self.factories, Role::Server, stream)?;
        Ok(InboundTransport::Stream(stream, sess))
    }
}

pub struct DatagramHandler {
    factories: Vec<Box<dyn UdpMaskFactory>>,
}

impl DatagramHandler {
    pub fn new(settings: &config::FinalmaskInboundSettings) -> Result<Self, FinalmaskError> {
        let template = parse_template(&settings.udp_template)?;
        let factories = build_udp_factories(&settings.udp, template.as_ref())?;
        Ok(DatagramHandler { factories })
    }
}

#[async_trait]
impl InboundDatagramHandler for DatagramHandler {
    async fn handle<'a>(&'a self, socket: AnyInboundDatagram) -> io::Result<AnyInboundTransport> {
        tracing::trace!("handling inbound finalmask datagram");
        let pipeline = masks::UdpPipeline::new(&self.factories, Role::Server)?;
        Ok(InboundTransport::Datagram(
            Box::new(MaskedInboundDatagram::new(socket, pipeline)),
            None,
        ))
    }
}
