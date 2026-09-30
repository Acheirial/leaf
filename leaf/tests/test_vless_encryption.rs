//! End-to-end VLESS `mlkem768x25519plus` encryption tests.
//!
//! These drive the real handshake between a client and a server over TCP. The
//! keys are the RFC 7748 X25519 test pair, so both scheme strings are
//! deterministic.

#![cfg(all(feature = "inbound-vless", feature = "outbound-vless"))]

use leaf::proxy::vless::encryption::{ClientInstance, ServerInstance};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// RFC 7748 §6.1: Alice's private key.
const SERVER_PRIVATE: &str = "dwdtCnMYpX08FsFyUbJmRd9ML4frwJkqsXf7pR25LCo";
/// RFC 7748 §6.1: `X25519(SERVER_PRIVATE, 9)`.
const CLIENT_PUBLIC: &str = "hSDwCYkwp1R0i33ctD73Wg2_Og0mOBr066SpjqqbTmo";
/// A public key that does *not* correspond to `SERVER_PRIVATE`.
const WRONG_PUBLIC: &str = "q6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6s";

fn server(decryption: &str) -> ServerInstance {
    ServerInstance::from_decryption(decryption).expect("server decryption scheme")
}

fn client(encryption: &str) -> ClientInstance {
    ClientInstance::from_encryption(encryption).expect("client encryption scheme")
}

/// Accepts one connection and echoes `hello world` as `pong!`. Returns `true`
/// when the encrypted handshake or the record layer failed.
async fn echo_server(port: u16, decryption: String) -> bool {
    let s = server(&decryption);
    let listener = TcpListener::bind(("127.0.0.1", port)).await.unwrap();
    let (sock, _) = listener.accept().await.unwrap();
    let mut stream = match s.handshake(Box::new(sock)).await {
        Ok(stream) => stream,
        Err(_) => return true,
    };
    let mut buf = vec![0u8; 11];
    if stream.read_exact(&mut buf).await.is_err() {
        return true;
    }
    if buf != b"hello world" {
        return true;
    }
    if stream.write_all(b"pong!").await.is_err() {
        return true;
    }
    stream.flush().await.is_err()
}

#[tokio::test]
async fn vless_encryption_round_trip() {
    let server_task = tokio::spawn(echo_server(
        5501,
        format!("mlkem768x25519plus.native.0s.{SERVER_PRIVATE}"),
    ));

    // Give the listener a moment to bind.
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    let sock = TcpStream::connect(("127.0.0.1", 5501)).await.unwrap();
    let c = client(&format!("mlkem768x25519plus.native.1rtt.{CLIENT_PUBLIC}"));
    let mut stream = c.handshake(Box::new(sock)).await.expect("client handshake");
    stream.write_all(b"hello world").await.unwrap();
    stream.flush().await.unwrap();
    let mut pong = [0u8; 5];
    stream.read_exact(&mut pong).await.unwrap();
    assert_eq!(&pong, b"pong!");
    assert!(
        !server_task.await.unwrap(),
        "the server handshake must succeed"
    );
}

#[tokio::test]
async fn vless_encryption_mismatched_key_fails_closed() {
    // The server keeps `SERVER_PRIVATE`; the client is configured with a
    // public key that does not match it, so no session key is shared.
    let server_task = tokio::spawn(echo_server(
        5502,
        format!("mlkem768x25519plus.native.0s.{SERVER_PRIVATE}"),
    ));

    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    let sock = TcpStream::connect(("127.0.0.1", 5502)).await.unwrap();
    let c = client(&format!("mlkem768x25519plus.native.1rtt.{WRONG_PUBLIC}"));

    // The server must not complete a handshake, and the client must never end
    // up with a usable record layer over a mismatched key.
    let client_handshake = c.handshake(Box::new(sock)).await;
    let server_failed = server_task.await.unwrap();
    assert!(
        server_failed,
        "the server must reject a mismatched client key"
    );
    assert!(
        client_handshake.is_err(),
        "the client must not establish a session against a mismatched server key"
    );
}
