use std::io;
use std::sync::Arc;

use async_trait::async_trait;
use tokio::io::AsyncWriteExt;
use uuid::Uuid;

use super::super::encoding::{self, Addons, CMD_TCP, FLOW_VISION};
use super::super::encryption::ClientInstance;
use super::super::stream::VisionStream;
use crate::app::SyncDnsClient;
use crate::config;
use crate::{proxy::*, session::*};

pub struct Handler {
    address: String,
    port: u16,
    uuid: [u8; 16],
    flow: Option<String>,
    encryption: Option<Arc<ClientInstance>>,
}

impl Handler {
    pub fn new(
        settings: &config::VlessOutboundSettings,
        _dns_client: SyncDnsClient,
    ) -> anyhow::Result<Self> {
        let uuid = Uuid::parse_str(&settings.uuid)
            .map_err(|e| anyhow::anyhow!("invalid vless uuid {}: {}", settings.uuid, e))?;
        let encryption = match settings.encryption.as_deref() {
            Some(e) if !e.is_empty() && e != "none" => {
                Some(Arc::new(ClientInstance::from_encryption(e)?))
            }
            _ => None,
        };
        Ok(Handler {
            address: settings.address.clone(),
            port: settings.port as u16,
            uuid: *uuid.as_bytes(),
            // The VLESS outbound settings carry no flow field, so the client
            // sends no flow at all: the addons blob is empty and the peer sees
            // a plain VLESS stream. Vision is a server side capability here.
            flow: None,
            encryption,
        })
    }
}

#[async_trait]
impl OutboundStreamHandler for Handler {
    fn connect_addr(&self) -> OutboundConnect {
        OutboundConnect::Proxy(Network::Tcp, self.address.clone(), self.port)
    }

    async fn handle<'a>(
        &'a self,
        sess: &'a Session,
        _lhs: Option<&mut AnyStream>,
        stream: Option<AnyStream>,
    ) -> io::Result<AnyStream> {
        tracing::trace!("handling outbound stream");
        let mut stream = stream.ok_or_else(|| io::Error::other("invalid input"))?;

        if let Some(encryption) = &self.encryption {
            stream = encryption.handshake(stream).await?;
        }

        let addons = Addons::new(self.flow.as_deref().unwrap_or(""));
        let header =
            encoding::encode_request_header(&self.uuid, CMD_TCP, &sess.destination, &addons);
        stream.write_all(&header).await?;
        stream.flush().await?;

        // The client stream always has to consume the server's response
        // header; the vision flow is layered on top of that when configured.
        Ok(Box::new(VisionStream::client(
            stream,
            self.uuid,
            self.flow.as_deref() == Some(FLOW_VISION),
        )))
    }
}
