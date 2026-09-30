use std::io;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use uuid::Uuid;

use super::super::encoding::{self, Addons, CMD_TCP, FLOW_VISION};
use super::super::encryption::ClientInstance;
use super::super::stream::VisionStream;
use super::super::vision::Padder;
use crate::app::SyncDnsClient;
use crate::config;
use crate::{proxy::*, session::*};

/// How long the client waits for the first payload before sending the empty
/// camouflage block, matching Xray's `500 * time.Millisecond` timeout.
const FIRST_PAYLOAD_TIMEOUT: Duration = Duration::from_millis(500);

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
            flow: settings.flow.clone().filter(|flow| !flow.is_empty()),
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
        lhs: Option<&mut AnyStream>,
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

        // The client stream always has to consume the server's response
        // header; the vision flow is layered on top of that when configured.
        if self.flow.as_deref() != Some(FLOW_VISION) {
            stream.flush().await?;
            return Ok(Box::new(VisionStream::client(stream, self.uuid, false)));
        }

        // Mirror Xray's first write: wait briefly for the first payload. When
        // it arrives it becomes the long-padded leading block; otherwise an
        // empty long-padded block is sent so the VLESS header does not stand
        // out as a short packet on its own.
        let mut padder = Padder::new(self.uuid);
        let mut first = Vec::new();
        if let Some(lhs) = lhs {
            match tokio::time::timeout(FIRST_PAYLOAD_TIMEOUT, lhs.read_buf(&mut first)).await {
                Ok(Ok(_)) => {}
                Ok(Err(e)) => return Err(e),
                Err(_) => first.clear(),
            }
        }
        stream.write_all(&padder.pad(&first)).await?;
        stream.flush().await?;

        Ok(Box::new(VisionStream::client_with_padder(
            stream, self.uuid, padder, true,
        )))
    }
}
