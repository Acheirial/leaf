use std::collections::HashMap;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use async_trait::async_trait;
use tokio::io::{AsyncRead, AsyncWriteExt, ReadBuf};

use super::datagram::Datagram;
use super::fallback::{self, Fallbacks};
use crate::config;
use crate::{proxy::*, session::*};

use super::super::encoding::{self, Addons, CMD_TCP, CMD_UDP, FLOW_VISION};
use super::super::encryption::ServerInstance;
use super::super::stream::VisionStream;

/// Users are matched by id with the two "route" bytes ignored, like Xray's
/// `vless.ProcessUUID`.
fn process_uuid(mut id: [u8; 16]) -> [u8; 16] {
    id[6] = 0;
    id[7] = 0;
    id
}

#[derive(Clone)]
struct User {
    /// The id as configured, kept for logging.
    id: [u8; 16],
    flow: String,
}

pub struct Handler {
    users: HashMap<[u8; 16], User>,
    fallbacks: Fallbacks,
    decryption: Option<Arc<ServerInstance>>,
}

impl Handler {
    pub fn new(settings: &config::VlessInboundSettings) -> anyhow::Result<Self> {
        let mut users: HashMap<[u8; 16], User> = HashMap::new();

        for id in settings.users.iter() {
            let uuid = uuid::Uuid::parse_str(id)
                .map_err(|e| anyhow::anyhow!("invalid vless user id {:?}: {}", id, e))?;
            let bytes = *uuid.as_bytes();
            users.insert(
                process_uuid(bytes),
                User {
                    id: bytes,
                    flow: String::new(),
                },
            );
        }

        for user in settings.user_objects.iter() {
            let id = user
                .id
                .as_deref()
                .ok_or_else(|| anyhow::anyhow!("vless user object is missing an id"))?;
            let uuid = uuid::Uuid::parse_str(id)
                .map_err(|e| anyhow::anyhow!("invalid vless user id {:?}: {}", id, e))?;
            let bytes = *uuid.as_bytes();
            let flow = user.flow.clone().unwrap_or_default();
            match flow.as_str() {
                "" | FLOW_VISION => {}
                other => {
                    return Err(anyhow::anyhow!(
                        "VLESS users: \"flow\" doesn't support {:?} in this version",
                        other
                    ))
                }
            }
            match user.encryption.as_deref() {
                None | Some("") | Some("none") => {}
                Some(_) => {
                    return Err(anyhow::anyhow!(
                        "VLESS users: \"encryption\" should not be in inbound settings"
                    ))
                }
            }
            users.insert(process_uuid(bytes), User { id: bytes, flow });
        }

        if users.is_empty() {
            return Err(anyhow::anyhow!("no VLESS users configured"));
        }

        let decryption = match settings.decryption.as_deref() {
            Some(d) if !d.is_empty() && d != "none" => {
                Some(Arc::new(ServerInstance::from_decryption(d)?))
            }
            _ => None,
        };

        // Xray refuses to combine an encrypted inbound with fallbacks
        // (`infra/conf/vless.go:157`): the decryption handshake consumes bytes
        // before the VLESS request is seen, so a fallback could not be handed
        // the connection verbatim.
        if decryption.is_some() && !settings.fallbacks.is_empty() {
            return Err(anyhow::anyhow!(
                "VLESS settings: \"fallbacks\" cannot be used together with \"decryption\""
            ));
        }

        let fallbacks = Fallbacks::new(&settings.fallbacks)?;

        Ok(Handler {
            users,
            fallbacks,
            decryption,
        })
    }

    async fn handle_fallback(
        &self,
        sess: Session,
        mut stream: AnyStream,
        seen: Vec<u8>,
    ) -> io::Result<AnyInboundTransport> {
        // Xray selects the fallback from the *outer* connection state, not from
        // anything sniffed from the payload: the server name and the negotiated
        // ALPN are populated by the TLS/REALITY inbound.
        let name = sess
            .outer_sni
            .clone()
            .or_else(|| sess.tls_sniffed_domain.clone())
            .unwrap_or_default()
            .to_lowercase();
        let alpn = sess.outer_alpn.clone().unwrap_or_default().to_lowercase();
        let path = fallback::http_path(&seen);
        let fb = self
            .fallbacks
            .select(&name, &alpn, &path)
            .ok_or_else(|| io::Error::other("no matching VLESS fallback"))?
            .clone();

        let mut conn = fb.dial().await?;
        if let Some(header) = fb.proxy_header(&sess) {
            conn.write_all(&header).await?;
        }
        if !seen.is_empty() {
            conn.write_all(&seen).await?;
        }
        conn.flush().await?;

        // The accept path only waits for the handshake; splice the fallback in
        // the background so the connection can live as long as either side.
        tokio::spawn(async move {
            if let Err(e) = tokio::io::copy_bidirectional(&mut stream, &mut conn).await {
                tracing::debug!("vless fallback ended: {}", e);
            }
        });

        Ok(InboundTransport::Empty)
    }
}

#[async_trait]
impl InboundStreamHandler for Handler {
    async fn handle<'a>(
        &'a self,
        mut sess: Session,
        stream: AnyStream,
    ) -> io::Result<AnyInboundTransport> {
        tracing::trace!("handling inbound vless stream");
        let mut stream = stream;
        if let Some(decryption) = &self.decryption {
            stream = decryption
                .handshake(stream)
                .await
                .map_err(|e| io::Error::other(format!("VLESS decryption failed: {}", e)))?;
        }

        let mut peek = PeekStream::new(stream);
        let request = match encoding::read_request(&mut peek).await {
            Ok(request) => request,
            Err(e) => {
                let seen = peek.take_seen();
                let stream = peek.into_inner();
                if self.fallbacks.is_empty() {
                    return Err(e);
                }
                tracing::debug!("vless request invalid ({}), trying a fallback", e);
                return self.handle_fallback(sess, stream, seen).await;
            }
        };
        // An unknown but well-formed user id is not fatal when fallbacks are
        // configured: Xray feeds the validator failure into the same fallback
        // path, replaying the bytes already read.
        let user = match self.users.get(&process_uuid(request.user)).cloned() {
            Some(user) => user,
            None => {
                let e = io::Error::other(format!(
                    "invalid VLESS request user id: {}",
                    uuid::Uuid::from_bytes(request.user)
                ));
                if self.fallbacks.is_empty() {
                    return Err(e);
                }
                let seen = peek.take_seen();
                let stream = peek.into_inner();
                tracing::debug!("vless request invalid ({}), trying a fallback", e);
                return self.handle_fallback(sess, stream, seen).await;
            }
        };
        let mut stream = peek.into_inner();

        // Flow policy, matching Xray: a flow may only be used by an account
        // configured for it, and a vision account may not be reached without
        // the flow (otherwise the outer TLS would carry a plain TLS stream).
        let vision = request.addons.flow == FLOW_VISION;
        match request.addons.flow.as_str() {
            FLOW_VISION => {
                if user.flow != FLOW_VISION {
                    return Err(io::Error::other(format!(
                        "vless account {} is not able to use the flow {}",
                        uuid::Uuid::from_bytes(user.id),
                        FLOW_VISION
                    )));
                }
            }
            "" => {
                if user.flow == FLOW_VISION && request.command == CMD_TCP {
                    return Err(io::Error::other(format!(
                        "vless account {} is rejected since the client flow is empty. \
                         Note that the pure TLS proxy has certain TLS in TLS characters.",
                        uuid::Uuid::from_bytes(user.id)
                    )));
                }
            }
            other => {
                return Err(io::Error::other(format!(
                    "unknown VLESS request flow {:?}",
                    other
                )))
            }
        }

        sess.destination = request.destination.clone();
        let user_uuid = request.user;

        // The server always answers with a response header; the client
        // consumes it before the body.
        let response_header = encoding::encode_response_header(&Addons::default());

        match request.command {
            CMD_TCP => {
                stream.write_all(&response_header).await?;
                stream.flush().await?;
                if vision {
                    Ok(InboundTransport::Stream(
                        Box::new(VisionStream::server(stream, user_uuid, true)),
                        sess,
                    ))
                } else {
                    Ok(InboundTransport::Stream(stream, sess))
                }
            }
            CMD_UDP => {
                if vision {
                    return Err(io::Error::other(
                        "xtls-rprx-vision does not support UDP without mux",
                    ));
                }
                stream.write_all(&response_header).await?;
                stream.flush().await?;
                let source = sess.source;
                let destination = request.destination.clone();
                Ok(InboundTransport::Datagram(
                    Box::new(Datagram::new(stream, source, destination)),
                    Some(sess),
                ))
            }
            other => Err(io::Error::other(format!(
                "unsupported VLESS request command {}",
                other
            ))),
        }
    }
}

/// Records every byte read from the inner stream so a failed header parse can
/// be handed to a fallback verbatim.
struct PeekStream<S> {
    inner: S,
    seen: Vec<u8>,
}

impl<S> PeekStream<S> {
    fn new(inner: S) -> Self {
        PeekStream {
            inner,
            seen: Vec::new(),
        }
    }

    fn take_seen(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.seen)
    }

    fn into_inner(self) -> S {
        self.inner
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for PeekStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let before = buf.filled().len();
        match Pin::new(&mut this.inner).poll_read(cx, buf) {
            Poll::Ready(Ok(())) => {
                let filled = buf.filled();
                if filled.len() > before {
                    this.seen.extend_from_slice(&filled[before..]);
                }
                Poll::Ready(Ok(()))
            }
            other => other,
        }
    }
}
