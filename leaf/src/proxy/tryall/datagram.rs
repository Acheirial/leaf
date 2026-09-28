use std::io;

use async_trait::async_trait;

use crate::{app::SyncDnsClient, proxy::*, session::Session};

pub struct Handler {
    pub actors: Vec<AnyOutboundHandler>,
    pub delay_base: u32,
    pub dns_client: SyncDnsClient,
}

#[async_trait]
impl OutboundDatagramHandler for Handler {
    fn connect_addr(&self) -> OutboundConnect {
        OutboundConnect::Unknown
    }

    fn transport_type(&self) -> DatagramTransportType {
        DatagramTransportType::Unknown
    }

    async fn handle<'a>(
        &'a self,
        sess: &'a Session,
        _transport: Option<AnyOutboundTransport>,
    ) -> io::Result<AnyOutboundDatagram> {
        tracing::trace!("handling outbound datagram");
        let (idx, dgram) = super::race(&self.actors, self.delay_base, |a, _i| async move {
            let transport =
                crate::proxy::connect_datagram_outbound(sess, self.dns_client.clone(), a).await?;
            a.datagram()?.handle(sess, transport).await
        })
        .await?;
        super::log_winner(sess, &self.actors, idx);
        Ok(dgram)
    }
}
