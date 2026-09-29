//! XHTTP has no datagram transport of its own.
//!
//! Xray registers `splithttp` as a stream transport only; UDP travels inside
//! the stream as an ordinary payload. The inbound manager still builds this
//! handler, so it exists and rejects what it is handed rather than pretending
//! to carry datagrams.

use std::io;

use anyhow::Result;
use async_trait::async_trait;

use crate::config;
use crate::proxy::*;

pub struct Handler;

impl Handler {
    pub fn new(_settings: &config::XhttpInboundSettings) -> Result<Self> {
        Ok(Handler)
    }
}

#[async_trait]
impl InboundDatagramHandler for Handler {
    async fn handle<'a>(&'a self, _socket: AnyInboundDatagram) -> io::Result<AnyInboundTransport> {
        Err(io::Error::other(
            "xhttp does not support an inbound datagram transport",
        ))
    }
}
