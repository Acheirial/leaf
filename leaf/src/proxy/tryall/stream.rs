use std::io;

use async_trait::async_trait;

use crate::{app::SyncDnsClient, proxy::*, session::Session};

pub struct Handler {
    pub actors: Vec<AnyOutboundHandler>,
    pub delay_base: u32,
    pub dns_client: SyncDnsClient,
}

#[async_trait]
impl OutboundStreamHandler for Handler {
    fn connect_addr(&self) -> OutboundConnect {
        OutboundConnect::Unknown
    }

    async fn handle<'a>(
        &'a self,
        sess: &'a Session,
        _lhs: Option<&mut AnyStream>,
        _stream: Option<AnyStream>,
    ) -> io::Result<AnyStream> {
        tracing::trace!("handling outbound stream");
        let (idx, stream) = super::race(&self.actors, self.delay_base, |a, _i| async move {
            let stream =
                crate::proxy::connect_stream_outbound(sess, self.dns_client.clone(), a).await?;
            a.stream()?.handle(sess, None, stream).await
        })
        .await?;
        super::log_winner(sess, &self.actors, idx);
        Ok(stream)
    }
}
