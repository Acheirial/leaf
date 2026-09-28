use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use futures::future::{abortable, BoxFuture};
use tokio::sync::{
    mpsc::{self, Sender},
    oneshot, Mutex, MutexGuard,
};
use tokio::task::JoinHandle;
use tracing::{debug, error, trace, warn, Instrument};

use crate::app::dispatcher::Dispatcher;
use crate::option;
use crate::session::{DatagramSource, Network, Session, SocksAddr};

#[derive(Debug)]
pub struct UdpPacket {
    pub data: Vec<u8>,
    pub src_addr: SocksAddr,
    pub dst_addr: SocksAddr,
}

impl UdpPacket {
    pub fn new(data: Vec<u8>, src_addr: SocksAddr, dst_addr: SocksAddr) -> Self {
        Self {
            data,
            src_addr,
            dst_addr,
        }
    }
}

type SessionMap = HashMap<DatagramSource, (Sender<UdpPacket>, oneshot::Sender<bool>, Instant)>;

pub struct NatManager {
    sessions: Arc<Mutex<SessionMap>>,
    dispatcher: Arc<Dispatcher>,
    timeout_check_task: Mutex<Option<BoxFuture<'static, ()>>>,
    timeout_check_handle: std::sync::Mutex<Option<JoinHandle<()>>>,
}

impl Drop for NatManager {
    fn drop(&mut self) {
        // Stop the periodic session sweeper if it was ever started.
        if let Ok(mut guard) = self.timeout_check_handle.lock() {
            if let Some(handle) = guard.take() {
                handle.abort();
            }
        }
    }
}

impl NatManager {
    pub fn new(dispatcher: Arc<Dispatcher>) -> Self {
        let sessions: Arc<Mutex<SessionMap>> = Arc::new(Mutex::new(HashMap::new()));
        let sessions2 = sessions.clone();

        // The task is lazy, will not run until any sessions added.
        let timeout_check_task: BoxFuture<'static, ()> = Box::pin(async move {
            loop {
                let mut sessions = sessions2.lock().await;
                let n_total = sessions.len();
                let now = Instant::now();
                let mut to_be_remove = Vec::new();
                for (key, val) in sessions.iter() {
                    if now.duration_since(val.2).as_secs() >= *option::UDP_SESSION_TIMEOUT {
                        to_be_remove.push(key.to_owned());
                    }
                }
                for key in to_be_remove.iter() {
                    if let Some(sess) = sessions.remove(key) {
                        // Sends a signal to abort downlink task, uplink task will
                        // end automatically when we drop the channel's tx side upon
                        // session removal.
                        if let Err(e) = sess.1.send(true) {
                            debug!("failed to send abort signal on session {}: {}", key, e);
                        }
                        debug!("udp session {} ended", key);
                    }
                }
                drop(to_be_remove); // drop explicitly
                let n_remaining = sessions.len();
                let n_removed = n_total - n_remaining;
                drop(sessions); // release the lock
                if n_removed > 0 {
                    debug!(
                        "removed {} nat sessions, remaining {} sessions",
                        n_removed, n_remaining
                    );
                }
                tokio::time::sleep(Duration::from_secs(
                    *option::UDP_SESSION_TIMEOUT_CHECK_INTERVAL,
                ))
                .await;
            }
        });

        NatManager {
            sessions,
            dispatcher,
            timeout_check_task: Mutex::new(Some(timeout_check_task)),
            timeout_check_handle: std::sync::Mutex::new(None),
        }
    }

    fn _send(&self, guard: &mut MutexGuard<'_, SessionMap>, key: &DatagramSource, pkt: UdpPacket) {
        let remove = match guard.get_mut(key) {
            Some(sess) => match sess.0.try_send(pkt) {
                Ok(()) => {
                    sess.2 = Instant::now(); // activity update
                    false
                }
                Err(mpsc::error::TrySendError::Full(_)) => {
                    // The uplink task is alive but busy. Keep the session alive
                    // unchanged (do not refresh its activity) and drop the packet.
                    trace!("send uplink packet failed: channel full for {}", key);
                    false
                }
                Err(mpsc::error::TrySendError::Closed(_)) => {
                    // The uplink task is gone, so no packet can ever reach the
                    // target again. Drop the session (dropping it also signals the
                    // downlink task to abort) instead of keeping it alive forever.
                    warn!("uplink channel closed for session {}, dropping it", key);
                    true
                }
            },
            None => {
                error!("no nat association found");
                false
            }
        };
        if remove {
            guard.remove(key);
        }
    }

    /// Runs the lazy session-cleanup task at most once, keeping a handle to it so
    /// it can be aborted when this manager is dropped.
    async fn ensure_sweeper_started(&self) {
        if let Some(task) = self.timeout_check_task.lock().await.take() {
            let handle = tokio::spawn(task);
            if let Ok(mut guard) = self.timeout_check_handle.lock() {
                *guard = Some(handle);
            }
        }
    }

    pub async fn send(
        &self,
        sess: Option<&Session>,
        dgram_src: &DatagramSource,
        inbound_tag: &str,
        client_ch_tx: &Sender<UdpPacket>,
        pkt: UdpPacket,
    ) {
        // Start the lazy sweeper before taking the sessions lock: no `.await`
        // may happen while the lock is held.
        self.ensure_sweeper_started().await;

        let mut guard = self.sessions.lock().await;

        if guard.contains_key(dgram_src) {
            self._send(&mut guard, dgram_src, pkt);
            return;
        }

        let mut sess = sess.cloned().unwrap_or_else(|| Session {
            network: Network::Udp,
            source: dgram_src.address,
            stream_id: dgram_src.stream_id,
            destination: pkt.dst_addr.clone(),
            inbound_tag: inbound_tag.to_string(),
            process_name: dgram_src.process_name.clone(),
            ..Default::default()
        });

        if sess.inbound_tag.is_empty() {
            sess.inbound_tag = inbound_tag.to_string();
        }

        sess.new_span();
        let span = sess.span();
        let _g = span.enter();

        // Always update destination to the packet's destination, because the session passed
        // from inbound listener might have a default (empty) destination.
        sess.destination = pkt.dst_addr.clone();

        // Register the session and build its channels while holding the lock, but
        // do not spawn any task here: spawning awaits and would serialize every
        // inbound packet behind the sessions mutex.
        let (target_ch_tx, target_ch_rx) = mpsc::channel(*crate::option::UDP_UPLINK_CHANNEL_SIZE);
        let (downlink_abort_tx, downlink_abort_rx) = oneshot::channel();

        guard.insert(
            dgram_src.clone(),
            (target_ch_tx.clone(), downlink_abort_tx, Instant::now()),
        );
        let n_sessions = guard.len();

        // Queue the very first packet before releasing the lock, so its delivery
        // is ordered ahead of any concurrent packet for the same source.
        if let Err(err) = target_ch_tx.try_send(pkt) {
            trace!("send uplink packet failed {}", err);
        }

        drop(guard);

        debug!(
            "added udp session {} -> {} ({})",
            &dgram_src, &sess.destination, n_sessions,
        );

        drop(_g);

        // The sessions guard has been released, so spawning is safe.
        self.spawn_session(
            sess,
            dgram_src.clone(),
            client_ch_tx.clone(),
            target_ch_rx,
            downlink_abort_rx,
            span,
        );
    }

    /// Spawns the dispatch/downlink/uplink tasks for a freshly registered session.
    ///
    /// MUST be called after the sessions mutex has been released: the spawned
    /// tasks lock the sessions map again.
    fn spawn_session(
        &self,
        sess: Session,
        raddr: DatagramSource,
        client_ch_tx: Sender<UdpPacket>,
        mut target_ch_rx: mpsc::Receiver<UdpPacket>,
        downlink_abort_rx: oneshot::Receiver<bool>,
        span: tracing::Span,
    ) {
        let dispatcher = self.dispatcher.clone();
        let sessions = self.sessions.clone();

        // Spawns a new task for dispatching to avoid blocking the current task,
        // because we have stream type transports for UDP traffic, establishing a
        // TCP stream would block the task.
        let raddr_cloned = raddr.clone();
        tokio::spawn(
            async move {
                // new socket to communicate with the target.
                let socket = match dispatcher
                    .dispatch_datagram(sess)
                    .instrument(tracing::Span::current())
                    .await
                {
                    Ok(s) => s,
                    Err(e) => {
                        debug!("dispatch {} failed: {}", &raddr_cloned, e);
                        sessions.lock().await.remove(&raddr_cloned);
                        return;
                    }
                };

                let (mut target_sock_recv, mut target_sock_send) = socket.split();

                // downlink
                let raddr_downlink = raddr_cloned.clone();
                let downlink_task = async move {
                    let mut buf = vec![0u8; *crate::option::DATAGRAM_BUFFER_SIZE * 1024];
                    loop {
                        match target_sock_recv.recv_from(&mut buf).await {
                            Err(err) => {
                                debug!(
                                    "Failed to receive downlink packets on session {}: {}",
                                    &raddr_downlink, err
                                );
                                break;
                            }
                            Ok((n, addr)) => {
                                trace!("outbound received udp packet src={} len={}", &addr, n);
                                let pkt = UdpPacket::new(
                                    buf[..n].to_vec(),
                                    addr.clone(),
                                    SocksAddr::from(raddr_downlink.address),
                                );
                                if let Err(err) = client_ch_tx.send(pkt).await {
                                    debug!(
                                        "Failed to send downlink packets on session {} to {}: {}",
                                        &raddr_downlink, &addr, err
                                    );
                                    break;
                                }

                                // activity update
                                {
                                    let mut sessions = sessions.lock().await;
                                    if let Some(sess) = sessions.get_mut(&raddr_downlink) {
                                        if addr.port() == 53 {
                                            // If the destination port is 53, we assume it's a
                                            // DNS query and set a negative timeout so it will
                                            // be removed on next check.
                                            if let Some(new_time) = sess.2.checked_sub(
                                                Duration::from_secs(*option::UDP_SESSION_TIMEOUT),
                                            ) {
                                                sess.2 = new_time;
                                            }
                                        } else {
                                            sess.2 = Instant::now();
                                        }
                                    }
                                }
                            }
                        }
                    }
                    sessions.lock().await.remove(&raddr_downlink);
                }
                .instrument(tracing::Span::current());

                let (downlink_task, downlink_task_handle) = abortable(downlink_task);
                tokio::spawn(downlink_task);

                // Runs a task to receive the abort signal.
                tokio::spawn(async move {
                    let _ = downlink_abort_rx.await;
                    downlink_task_handle.abort();
                });

                // uplink
                let raddr_uplink = raddr_cloned.clone();
                tokio::spawn(
                    async move {
                        while let Some(pkt) = target_ch_rx.recv().await {
                            trace!(
                                "outbound send udp packet dst={} len={}",
                                &pkt.dst_addr,
                                pkt.data.len()
                            );
                            if let Err(e) = target_sock_send.send_to(&pkt.data, &pkt.dst_addr).await
                            {
                                debug!(
                                    "Failed to send uplink packets on session {} to {}: {:?}",
                                    &raddr_uplink, &pkt.dst_addr, e
                                );
                                break;
                            }
                        }
                        if let Err(e) = target_sock_send.close().await {
                            debug!("Failed to close outbound datagram {}: {}", &raddr_uplink, e);
                        }
                    }
                    .instrument(tracing::Span::current()),
                );
            }
            .instrument(span),
        );
    }
}
