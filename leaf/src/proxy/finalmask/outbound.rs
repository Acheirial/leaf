//! The outbound half of a FinalMask transport pair.
//!
//! An outbound mask wraps what goes onto the wire: a stream handler wraps the
//! dialled stream, a datagram handler wraps the datagram the chain handed it.
//! Both build a fresh, stateful chain for every connection, in [`Role::Client`].

use std::io;

use async_trait::async_trait;

use crate::config;
use crate::proxy::*;
use crate::session::Session;

use super::datagram::MaskedOutboundDatagram;
use super::masks::{self, Role, TcpMaskFactory, UdpMaskFactory};
use super::{build_tcp_factories, build_udp_factories, parse_template, FinalmaskError};

pub struct StreamHandler {
    factories: Vec<Box<dyn TcpMaskFactory>>,
}

impl StreamHandler {
    pub fn new(settings: &config::FinalmaskOutboundSettings) -> Result<Self, FinalmaskError> {
        let template = parse_template(&settings.tcp_template)?;
        let factories = build_tcp_factories(&settings.tcp, template.as_ref())?;
        Ok(StreamHandler { factories })
    }
}

#[async_trait]
impl OutboundStreamHandler for StreamHandler {
    fn connect_addr(&self) -> OutboundConnect {
        // A mask is a transport pair: it wraps whatever the actor inside it
        // dials, so it leaves the address to that actor.
        OutboundConnect::Next
    }

    async fn handle<'a>(
        &'a self,
        _sess: &'a Session,
        _lhs: Option<&mut AnyStream>,
        stream: Option<AnyStream>,
    ) -> io::Result<AnyStream> {
        tracing::trace!("handling outbound finalmask stream");
        let raw = stream.ok_or_else(|| {
            io::Error::other("finalmask stream handler requires an underlying stream")
        })?;
        masks::build_tcp(&self.factories, Role::Client, raw)
    }
}

pub struct DatagramHandler {
    factories: Vec<Box<dyn UdpMaskFactory>>,
}

impl DatagramHandler {
    pub fn new(settings: &config::FinalmaskOutboundSettings) -> Result<Self, FinalmaskError> {
        let template = parse_template(&settings.udp_template)?;
        let factories = build_udp_factories(&settings.udp, template.as_ref())?;
        Ok(DatagramHandler { factories })
    }
}

#[async_trait]
impl OutboundDatagramHandler for DatagramHandler {
    fn connect_addr(&self) -> OutboundConnect {
        OutboundConnect::Next
    }

    fn transport_type(&self) -> DatagramTransportType {
        // Masks keep the datagram shape; they do not add reliability.
        DatagramTransportType::Unreliable
    }

    async fn handle<'a>(
        &'a self,
        _sess: &'a Session,
        transport: Option<AnyOutboundTransport>,
    ) -> io::Result<AnyOutboundDatagram> {
        tracing::trace!("handling outbound finalmask datagram");
        match transport {
            Some(OutboundTransport::Datagram(inner)) => {
                let pipeline = masks::UdpPipeline::new(&self.factories, Role::Client)?;
                Ok(Box::new(MaskedOutboundDatagram::new(inner, pipeline)))
            }
            Some(OutboundTransport::Stream(_)) => Err(io::Error::other(
                "finalmask datagram handler cannot mask a reliable stream",
            )),
            None => Err(io::Error::other(
                "finalmask datagram handler requires an underlying datagram",
            )),
        }
    }
}
