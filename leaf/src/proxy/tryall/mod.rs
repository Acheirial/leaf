pub mod datagram;
pub mod stream;

use std::{future::Future, io, time::Duration};

use futures::future::select_ok;
use tracing::debug;

use crate::{proxy::AnyOutboundHandler, session::Session};

pub use datagram::Handler as DatagramHandler;
pub use stream::Handler as StreamHandler;

/// Log the actor that won a [`race`], keeping the historic log line in one
/// place for both the stream and datagram handlers.
pub(crate) fn log_winner(sess: &Session, actors: &[AnyOutboundHandler], idx: usize) {
    debug!(
        "tryall handles [{}:{}] to [{}]",
        sess.network,
        sess.destination,
        actors[idx].tag()
    );
}

/// Race every actor in `actors`, dialling and handing off to each actor's own
/// handler through `attempt`. The first successful attempt wins.
///
/// `delay_base` staggers the attempts: actor `i` waits `delay_base * i`
/// milliseconds before starting. The returned index identifies the winning
/// actor so the caller can log it.
pub(crate) async fn race<'a, T, F, Fut>(
    actors: &'a [AnyOutboundHandler],
    delay_base: u32,
    attempt: F,
) -> io::Result<(usize, T)>
where
    F: Fn(&'a AnyOutboundHandler, usize) -> Fut,
    Fut: Future<Output = io::Result<T>>,
{
    let mut tasks = Vec::new();
    for (i, a) in actors.iter().enumerate() {
        let fut = attempt(a, i);
        let task = async move {
            if delay_base > 0 {
                tokio::time::sleep(Duration::from_millis((delay_base * i as u32) as u64)).await;
            }
            fut.await.map(|v| (i, v))
        };
        tasks.push(Box::pin(task));
    }
    match select_ok(tasks.into_iter()).await {
        Ok(v) => Ok(v.0),
        Err(e) => Err(io::Error::other(format!(
            "all outbound attempts failed, last error: {}",
            e
        ))),
    }
}
