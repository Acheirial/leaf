use std::io::{self};
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::RwLock;
use tracing::{debug, info, warn, Instrument};

use crate::{
    app::SyncDnsClient,
    common::{
        self,
        dns_sniff::{DnsSniffer, SniffingDatagram},
        sniff,
    },
    option,
    proxy::*,
    session::*,
};

use tokio::io::AsyncWriteExt;

async fn healthcheck_respond_simple<T>(stream: &mut T) -> io::Result<()>
where
    T: AsyncWrite + Unpin,
{
    stream.write_all(b"PONG").await?;
    stream.flush().await?;
    Ok(())
}

use crate::app::SyncStatManager;

use super::outbound::manager::OutboundManager;
use super::router::Router;

struct HealthcheckUdpRecvHalf {
    responded: bool,
    src_addr: SocksAddr,
}

#[async_trait::async_trait]
impl OutboundDatagramRecvHalf for HealthcheckUdpRecvHalf {
    async fn recv_from(&mut self, buf: &mut [u8]) -> io::Result<(usize, SocksAddr)> {
        if self.responded {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "no more data"));
        }
        let pong = b"PONG";
        if buf.len() < pong.len() {
            return Err(io::Error::other("buffer too small"));
        }
        buf[..pong.len()].copy_from_slice(pong);
        self.responded = true;
        Ok((pong.len(), self.src_addr.clone()))
    }
}

struct HealthcheckUdpSendHalf;

#[async_trait::async_trait]
impl OutboundDatagramSendHalf for HealthcheckUdpSendHalf {
    async fn send_to(&mut self, buf: &[u8], _dst_addr: &SocksAddr) -> io::Result<usize> {
        Ok(buf.len())
    }

    async fn close(&mut self) -> io::Result<()> {
        Ok(())
    }
}

struct HealthcheckUdpDatagram {
    recv: HealthcheckUdpRecvHalf,
    send: HealthcheckUdpSendHalf,
}

impl OutboundDatagram for HealthcheckUdpDatagram {
    fn split(
        self: Box<Self>,
    ) -> (
        Box<dyn OutboundDatagramRecvHalf>,
        Box<dyn OutboundDatagramSendHalf>,
    ) {
        (Box::new(self.recv), Box::new(self.send))
    }
}

#[inline]
fn log_request(sess: &Session, outbound_tag: &str, handshake_time: Option<u128>) {
    let hs = handshake_time.map_or("failed".to_string(), |hs| format!("{}ms", hs));
    let network = sess.network.to_string();

    #[cfg(feature = "rule-process-name")]
    {
        let process_name = sess
            .process_name
            .as_ref()
            .map(|x| {
                std::path::Path::new(x)
                    .file_name()
                    .and_then(|name| name.to_str())
                    .unwrap_or(x)
            })
            .unwrap_or("");
        info!(
            "handled process={} src={} proto={} in={} out={} connect={} dst={}",
            process_name,
            sess.forwarded_source.unwrap_or_else(|| sess.source.ip()),
            network,
            &sess.inbound_tag,
            outbound_tag,
            hs,
            &sess.destination,
        );
    }

    #[cfg(not(feature = "rule-process-name"))]
    {
        info!(
            "handled src={} proto={} in={} out={} connect={} dst={}",
            sess.forwarded_source.unwrap_or_else(|| sess.source.ip()),
            network,
            &sess.inbound_tag,
            outbound_tag,
            hs,
            &sess.destination,
        );
    }
}

/// Outcome of picking an outbound for a session.
enum PickOutbound {
    /// A route was picked (or fell back to the default handler). `handler` is
    /// the resolved outbound handler, if one exists for `tag`.
    Picked {
        tag: String,
        is_default: bool,
        handler: Option<AnyOutboundHandler>,
    },
    /// No route matched and no default handler is configured.
    NoOutbound,
}

pub struct Dispatcher {
    pub(crate) outbound_manager: Arc<RwLock<OutboundManager>>,
    pub(crate) router: Arc<RwLock<Arc<Router>>>,
    dns_client: SyncDnsClient,
    stat_manager: SyncStatManager,
    dns_sniffer: DnsSniffer,
}

impl Dispatcher {
    pub fn new(
        outbound_manager: Arc<RwLock<OutboundManager>>,
        router: Arc<RwLock<Arc<Router>>>,
        dns_client: SyncDnsClient,
        stat_manager: SyncStatManager,
    ) -> Self {
        Dispatcher {
            outbound_manager,
            router,
            dns_client,
            stat_manager,
            dns_sniffer: DnsSniffer::new(),
        }
    }

    /// Snapshot the router, pick an outbound route for `sess`, fall back to the
    /// default handler, record `sess.outbound_tag` and resolve the handler from
    /// the outbound manager. The router read guard is released before any
    /// `await` so a concurrent reload cannot deadlock the runtime.
    async fn pick_outbound(&self, sess: &mut Session) -> anyhow::Result<PickOutbound> {
        let router = self.router.read().await.clone();
        let (tag, is_default) = match router.pick_route(&*sess).await? {
            Some(tag) => (tag.to_owned(), false),
            None => match self.outbound_manager.read().await.default_handler() {
                Some(tag) => (tag, true),
                None => return Ok(PickOutbound::NoOutbound),
            },
        };
        sess.outbound_tag = tag.clone();
        let handler = self.outbound_manager.read().await.get(&tag);
        Ok(PickOutbound::Picked {
            tag,
            is_default,
            handler,
        })
    }

    pub async fn dispatch_stream<T>(&self, sess: Session, lhs: T)
    where
        T: 'static + AsyncRead + AsyncWrite + Unpin + Send + Sync,
    {
        let span = sess.span();
        self.dispatch_stream_inner(sess, lhs).instrument(span).await
    }

    async fn dispatch_stream_inner<T>(&self, mut sess: Session, mut lhs: T)
    where
        T: 'static + AsyncRead + AsyncWrite + Unpin + Send + Sync,
    {
        debug!(
            "dispatch proto={} in={} src={} dst={}",
            &sess.network, &sess.inbound_tag, &sess.source, &sess.destination
        );

        if option::DNS_DOMAIN_SNIFFING.load(std::sync::atomic::Ordering::Relaxed) {
            if let Some(ip) = sess.destination.ip() {
                if let Some(domain) = self.dns_sniffer.get(&ip).await {
                    debug!("dns sniffed domain={}", &domain);
                    sess.dns_sniffed_domain = Some(domain);
                }
            }
        }

        if let Some(domain) = sess.destination.domain() {
            if domain == "healthcheck.leaf" {
                if let Err(e) = healthcheck_respond_simple(&mut lhs).await {
                    debug!("healthcheck response failed: {}", e);
                }
                return;
            }
        }

        let tls_sniff = option::TLS_DOMAIN_SNIFFING.load(std::sync::atomic::Ordering::Relaxed);
        let tls_sniff_all =
            option::TLS_DOMAIN_SNIFFING_ALL.load(std::sync::atomic::Ordering::Relaxed);
        let http_sniff = option::HTTP_DOMAIN_SNIFFING.load(std::sync::atomic::Ordering::Relaxed);
        let http_sniff_all =
            option::HTTP_DOMAIN_SNIFFING_ALL.load(std::sync::atomic::Ordering::Relaxed);

        let is_tls_port = sess.destination.port() == 443;
        let is_http_port = sess.destination.port() == 80;

        let do_tls = (tls_sniff && is_tls_port) || tls_sniff_all;
        let do_http = (http_sniff && is_http_port) || http_sniff_all;

        let mut lhs: Box<dyn ProxyStream> = if (do_tls || do_http) && sniff::should_sniff(&sess) {
            let mut lhs = sniff::SniffingStream::new(lhs);
            match lhs.sniff(&sess).await {
                Ok(res) => {
                    if let Some((kind, domain)) = res {
                        debug!("sniffed domain={}", &domain);
                        match kind {
                            sniff::SniffKind::Tls => {
                                if do_tls {
                                    sess.tls_sniffed_domain = Some(domain.clone());
                                }
                            }
                            sniff::SniffKind::Http => {
                                if do_http {
                                    sess.http_sniffed_domain = Some(domain.clone());
                                }
                            }
                        }

                        if option::DOMAIN_OVERRIDE.load(std::sync::atomic::Ordering::Relaxed) {
                            if let Ok(dest) = SocksAddr::try_from((domain, sess.destination.port()))
                            {
                                debug!("override destination with sniffed domain={}", dest);
                                sess.destination = dest;
                            }
                        }
                    }
                }
                Err(e) => {
                    debug!("sniff err={}", e);
                    return;
                }
            }
            Box::new(lhs)
        } else {
            Box::new(lhs)
        };

        let h = match self.pick_outbound(&mut sess).await {
            Ok(PickOutbound::Picked {
                tag,
                is_default,
                handler,
            }) => {
                if is_default {
                    debug!("picked default out={}", &tag);
                } else {
                    debug!(
                        "picked route out={} src={} dst={}",
                        &tag, &sess.source, &sess.destination
                    );
                }
                if let Some(h) = handler {
                    h
                } else {
                    // FIXME use  the default handler
                    warn!("handler not found");
                    return;
                }
            }
            Ok(PickOutbound::NoOutbound) => {
                warn!("no outbound found");
                return;
            }
            Err(err) => {
                debug!("pick route err={}", err);
                return;
            }
        };

        let handshake_start = tokio::time::Instant::now();
        let stream =
            match crate::proxy::connect_stream_outbound(&sess, self.dns_client.clone(), &h).await {
                Ok(s) => s,
                Err(e) => {
                    debug!(
                        "connect outbound src={} dst={} out={} err={}",
                        &sess.source,
                        &sess.destination,
                        &h.tag(),
                        e
                    );
                    log_request(&sess, h.tag(), None);
                    return;
                }
            };

        let stream = if let Some(s) = stream {
            let s = self.stat_manager.write().await.stat_stream(s, sess.clone());
            Some(s)
        } else {
            lhs = self
                .stat_manager
                .write()
                .await
                .stat_inbound_stream(lhs, sess.clone());
            None
        };

        let th = match h.stream() {
            Ok(th) => th,
            Err(e) => {
                debug!("get stream handler, err={}", e);
                return;
            }
        };
        match th.handle(&sess, Some(&mut lhs), stream).await {
            Ok(mut rhs) => {
                let elapsed = tokio::time::Instant::now().duration_since(handshake_start);

                log_request(&sess, h.tag(), Some(elapsed.as_millis()));

                match common::io::copy_buf_bidirectional_with_timeout(
                    &mut lhs,
                    &mut rhs,
                    *option::LINK_BUFFER_SIZE * 1024,
                    Duration::from_secs(*option::TCP_UPLINK_TIMEOUT),
                    Duration::from_secs(*option::TCP_DOWNLINK_TIMEOUT),
                )
                .await
                {
                    Ok(_) => {
                        debug!("transfer end");
                    }
                    Err(e) => {
                        debug!("transfer err={}", e);
                    }
                }
            }
            Err(e) => {
                debug!("outbound handle err={}", e);
                log_request(&sess, h.tag(), None);
            }
        }
    }

    pub async fn dispatch_stream_outbound(&self, mut sess: Session) -> io::Result<AnyStream> {
        let h = match self.pick_outbound(&mut sess).await {
            Ok(PickOutbound::Picked { handler, .. }) => {
                handler.ok_or_else(|| io::Error::other("handler not found"))?
            }
            Ok(PickOutbound::NoOutbound) => return Err(io::Error::other("no outbound found")),
            Err(_) => return Err(io::Error::other("pick route failed")),
        };

        let stream =
            crate::proxy::connect_stream_outbound(&sess, self.dns_client.clone(), &h).await?;
        h.stream()?.handle(&sess, None, stream).await
    }

    pub async fn dispatch_datagram(
        &self,
        mut sess: Session,
    ) -> io::Result<Box<dyn OutboundDatagram>> {
        debug!(
            "dispatch proto={} in={} src={} dst={}",
            &sess.network, &sess.inbound_tag, &sess.source, &sess.destination
        );

        if option::DNS_DOMAIN_SNIFFING.load(std::sync::atomic::Ordering::Relaxed) {
            if let Some(ip) = sess.destination.ip() {
                if let Some(domain) = self.dns_sniffer.get(&ip).await {
                    debug!("dns sniffed domain={}", &domain);
                    sess.dns_sniffed_domain = Some(domain);
                }
            }
        }

        if let Some(domain) = sess.destination.domain() {
            if domain == "healthcheck.leaf" {
                let recv = HealthcheckUdpRecvHalf {
                    responded: false,
                    src_addr: sess.destination.clone(),
                };
                let d = HealthcheckUdpDatagram {
                    recv,
                    send: HealthcheckUdpSendHalf,
                };
                let d: Box<dyn OutboundDatagram> = Box::new(d);
                return Ok(d);
            }
        }

        let h = match self.pick_outbound(&mut sess).await {
            Ok(PickOutbound::Picked {
                tag,
                is_default,
                handler,
            }) => {
                if is_default {
                    debug!("picked default out={}", &tag);
                } else {
                    debug!(
                        "picked route out={} src={} dst={}",
                        &tag, &sess.source, &sess.destination
                    );
                }
                if let Some(h) = handler {
                    h
                } else {
                    warn!("handler not found");
                    return Err(io::Error::other("handler not found"));
                }
            }
            Ok(PickOutbound::NoOutbound) => {
                warn!("no outbound found");
                return Err(io::Error::other("no outbound found"));
            }
            Err(err) => {
                debug!("pick route err={}", err);
                return Err(io::Error::other("pick route failed"));
            }
        };

        let handshake_start = tokio::time::Instant::now();

        debug!("connect datagram outbound={}", h.tag());
        let transport =
            crate::proxy::connect_datagram_outbound(&sess, self.dns_client.clone(), &h).await?;

        match h.datagram()?.handle(&sess, transport).await {
            Ok(mut d) => {
                let elapsed = tokio::time::Instant::now().duration_since(handshake_start);

                log_request(&sess, h.tag(), Some(elapsed.as_millis()));

                d = self
                    .stat_manager
                    .write()
                    .await
                    .stat_outbound_datagram(d, sess.clone());

                if option::DNS_DOMAIN_SNIFFING.load(std::sync::atomic::Ordering::Relaxed)
                    && sess.destination.port() == 53
                {
                    d = Box::new(SniffingDatagram::new(d, self.dns_sniffer.clone()));
                }

                Ok(d)
            }
            Err(e) => {
                debug!("outbound handle err={}", e);
                log_request(&sess, h.tag(), None);
                Err(e)
            }
        }
    }

    pub async fn is_direct_outbound(&self, tag: &str) -> bool {
        if let Some(h) = self.outbound_manager.read().await.get(tag) {
            h.is_direct()
        } else {
            false
        }
    }
}
