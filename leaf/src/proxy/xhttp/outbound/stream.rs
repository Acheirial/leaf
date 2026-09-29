use std::io;
use std::sync::Arc;

use anyhow::Result;
use async_trait::async_trait;

use crate::app::SyncDnsClient;
use crate::config;
use crate::proxy::xhttp::config::Config as XhttpConfig;
use crate::proxy::*;
use crate::session::Session;

use super::client;

pub struct Handler {
    config: Arc<XhttpConfig>,
    dns_client: SyncDnsClient,
}

impl Handler {
    pub fn new(
        settings: &config::XhttpOutboundSettings,
        dns_client: SyncDnsClient,
    ) -> Result<Self> {
        let config = XhttpConfig::from_outbound(settings)?;
        Ok(Handler {
            config: Arc::new(config),
            dns_client,
        })
    }
}

#[async_trait]
impl OutboundStreamHandler for Handler {
    fn connect_addr(&self) -> OutboundConnect {
        // The transport wraps whatever the chain dialled; the address comes
        // from the actor that names an endpoint.
        OutboundConnect::Next
    }

    async fn handle<'a>(
        &'a self,
        sess: &'a Session,
        _lhs: Option<&mut AnyStream>,
        stream: Option<AnyStream>,
    ) -> io::Result<AnyStream> {
        let stream =
            stream.ok_or_else(|| io::Error::other("xhttp outbound was handed no connection"))?;
        let dest = sess.destination.clone();
        match self.config.resolved_mode().as_str() {
            "stream-one" => client::stream_one(self.config.clone(), stream, dest).await,
            "stream-up" => {
                client::stream_up(self.config.clone(), self.dns_client.clone(), stream, dest).await
            }
            _ => {
                client::packet_up(self.config.clone(), self.dns_client.clone(), stream, dest).await
            }
        }
    }
}
