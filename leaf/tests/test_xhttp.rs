mod common;

use std::path::PathBuf;
use std::time::Duration;

use rand::{rngs::StdRng, RngCore, SeedableRng};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use leaf::session::{Session, SocksAddr};

fn config1(mode: &str, socks_port: u16, server_port: u16) -> String {
    format!(
        r#"{{
    "log": {{ "level": "trace" }},
    "inbounds": [
        {{ "protocol": "socks", "address": "127.0.0.1", "port": {socks_port} }}
    ],
    "outbounds": [
        {{ "protocol": "chain", "settings": {{ "actors": ["xhttp", "socks"] }} }},
        {{ "protocol": "xhttp", "tag": "xhttp", "settings": {{ "path": "/leaf", "mode": "{mode}" }} }},
        {{ "protocol": "socks", "tag": "socks", "settings": {{ "address": "127.0.0.1", "port": {server_port} }} }}
    ]
}}"#
    )
}

fn config2(mode: &str, server_port: u16) -> String {
    format!(
        r#"{{
    "log": {{ "level": "trace" }},
    "inbounds": [
        {{
            "protocol": "chain",
            "address": "127.0.0.1",
            "port": {server_port},
            "settings": {{ "actors": ["xhttp", "socks"] }}
        }},
        {{ "protocol": "xhttp", "tag": "xhttp", "settings": {{ "path": "/leaf", "mode": "{mode}" }} }},
        {{ "protocol": "socks", "tag": "socks" }}
    ],
    "outbounds": [
        {{ "protocol": "direct" }}
    ]
}}"#
    )
}

fn file_hash(path: &PathBuf) -> anyhow::Result<Vec<u8>> {
    let data = std::fs::read(path)?;
    let mut hasher = Sha256::new();
    hasher.update(&data);
    Ok(hasher.finalize().to_vec())
}

/// A socks client session aimed at `addr`.
fn session_to(addr: std::net::SocketAddr) -> Session {
    let mut sess = Session::default();
    sess.destination = SocksAddr::Ip(addr);
    sess
}

async fn echo_round_trip(socks_port: u16) -> anyhow::Result<()> {
    let (addr, echo) = common::run_tcp_echo_server("127.0.0.1:0").await?;
    let echo = tokio::spawn(echo);

    let sess = session_to(addr);
    let mut stream = common::new_socks_stream("127.0.0.1", socks_port, &sess, None, None).await?;
    stream.write_all(b"abc").await?;
    let mut buf = Vec::new();
    let n = stream.read_buf(&mut buf).await?;
    anyhow::ensure!(&buf[..n] == b"abc", "echo mismatch: {:?}", &buf[..n]);

    drop(stream);
    echo.abort();
    Ok(())
}

/// 2 MiB in each direction through the proxy, verified by hash: once
/// proxy-client to remote (the uplink) and once remote to proxy-client (the
/// downlink).
async fn transfer_2mib(socks_port: u16, src: PathBuf) -> anyhow::Result<()> {
    // Downlink: the remote sends, the client through the proxy receives.
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let src_for_send = src.clone();
    let sender = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await?;
        let data = std::fs::read(&src_for_send)?;
        stream.write_all(&data).await?;
        stream.shutdown().await?;
        Ok::<(), anyhow::Error>(())
    });

    let down = PathBuf::from(format!("{}.down", src.display()));
    let sess = session_to(addr);
    let mut stream = common::new_socks_stream("127.0.0.1", socks_port, &sess, None, None).await?;
    let mut file = tokio::fs::File::create(&down).await?;
    tokio::io::copy(&mut stream, &mut file).await?;
    file.sync_all().await?;
    drop(file);
    drop(stream);
    sender.await??;
    anyhow::ensure!(
        file_hash(&src)? == file_hash(&down)?,
        "downlink 2 MiB mismatch"
    );

    // Uplink: the client through the proxy sends, the remote receives.
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let up = PathBuf::from(format!("{}.up", src.display()));
    let up_for_recv = up.clone();
    let receiver = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await?;
        let mut file = tokio::fs::File::create(&up_for_recv).await?;
        tokio::io::copy(&mut stream, &mut file).await?;
        file.sync_all().await?;
        Ok::<(), anyhow::Error>(())
    });

    let sess = session_to(addr);
    let mut stream = common::new_socks_stream("127.0.0.1", socks_port, &sess, None, None).await?;
    let mut file = tokio::fs::File::open(&src).await?;
    tokio::io::copy(&mut file, &mut stream).await?;
    drop(file);
    drop(stream);
    receiver.await??;
    anyhow::ensure!(file_hash(&src)? == file_hash(&up)?, "uplink 2 MiB mismatch");

    let _ = std::fs::remove_file(&down);
    let _ = std::fs::remove_file(&up);
    Ok(())
}

async fn wait_shutdown(id: leaf::RuntimeId) {
    while leaf::is_running(id) {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

fn run_mode(mode: &str, socks_port: u16, server_port: u16) -> anyhow::Result<()> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| anyhow::anyhow!("build runtime failed: {}", e))?;

    let configs = vec![
        config1(mode, socks_port, server_port),
        config2(mode, server_port),
    ];

    let dir = format!("/home/dev/tmp/test_xhttp_{}_{}", mode, socks_port);
    let src = PathBuf::from(format!("{}.src", dir));
    let mut rng = StdRng::seed_from_u64(0x7850_494e_5448 ^ socks_port as u64);
    let mut data = vec![0u8; 2 * 1024 * 1024];
    rng.fill_bytes(&mut data);
    std::fs::write(&src, &data).map_err(|e| anyhow::anyhow!("write source failed: {}", e))?;

    let ids = common::run_leaf_instances(&rt, configs)?;
    let src_for_app = src.clone();
    let res = rt.block_on(rt.spawn(async move {
        tokio::time::sleep(Duration::from_millis(200)).await;
        echo_round_trip(socks_port).await?;
        transfer_2mib(socks_port, src_for_app).await
    }));

    for id in ids {
        leaf::shutdown(id);
        let _ = rt.block_on(rt.spawn(async move { wait_shutdown(id).await }));
    }
    let _ = std::fs::remove_file(&src);

    match res {
        Ok(Ok(())) => Ok(()),
        Ok(Err(e)) => Err(e),
        Err(e) => Err(anyhow::anyhow!("task join failed: {}", e)),
    }
}

#[cfg(all(
    feature = "outbound-socks",
    feature = "inbound-socks",
    feature = "outbound-xhttp",
    feature = "inbound-xhttp",
    feature = "outbound-direct",
    feature = "inbound-chain",
    feature = "outbound-chain",
))]
#[test]
fn test_xhttp_packet_up() -> anyhow::Result<()> {
    run_mode("packet-up", 5101, 5102)
}

#[cfg(all(
    feature = "outbound-socks",
    feature = "inbound-socks",
    feature = "outbound-xhttp",
    feature = "inbound-xhttp",
    feature = "outbound-direct",
    feature = "inbound-chain",
    feature = "outbound-chain",
))]
#[test]
fn test_xhttp_stream_up() -> anyhow::Result<()> {
    run_mode("stream-up", 5103, 5104)
}

#[cfg(all(
    feature = "outbound-socks",
    feature = "inbound-socks",
    feature = "outbound-xhttp",
    feature = "inbound-xhttp",
    feature = "outbound-direct",
    feature = "inbound-chain",
    feature = "outbound-chain",
))]
#[test]
fn test_xhttp_stream_one() -> anyhow::Result<()> {
    run_mode("stream-one", 5105, 5106)
}

#[cfg(all(
    feature = "outbound-socks",
    feature = "inbound-socks",
    feature = "outbound-xhttp",
    feature = "inbound-xhttp",
    feature = "outbound-direct",
    feature = "inbound-chain",
    feature = "outbound-chain",
))]
#[test]
fn test_xhttp_auto() -> anyhow::Result<()> {
    run_mode("auto", 5107, 5108)
}
