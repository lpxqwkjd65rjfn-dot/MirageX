//! End-to-end loopback integration test for the beta release.
//!
//! Boots the engine in-process with:
//!   inbound  = SOCKS5 on 127.0.0.1:<ephemeral>
//!   outbound = Direct
//!   routing  = default → direct
//!
//! Then opens an echo server on a second port, asks the SOCKS5 inbound to
//! CONNECT to it, sends payload bytes and checks that they round-trip.
//!
//! This is the "stable beta" smoke test: if it passes, `miragex run` can
//! actually carry traffic. If it ever breaks, the beta tag is invalid.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use mirage_config::inbound::{InboundConfig, InboundKind, SocksInbound};
use mirage_config::log::LogConfig;
use mirage_config::mobile::MobileConfig;
use mirage_config::outbound::{DirectOutbound, OutboundConfig, OutboundKind};
use mirage_config::routing::{DnsConfig, RoutingConfig};
use mirage_config::Config;
use mirage_engine::Engine;

/// Find an unused TCP port by binding ephemeral, querying, then dropping.
async fn pick_port() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    drop(l);
    port
}

/// Spawn a TCP echo server on 127.0.0.1:`port`; returns when it's bound.
async fn spawn_echo(port: u16) {
    let listener = TcpListener::bind(("127.0.0.1", port)).await.unwrap();
    tokio::spawn(async move {
        loop {
            let (mut sock, _) = match listener.accept().await {
                Ok(v) => v,
                Err(_) => return,
            };
            tokio::spawn(async move {
                let mut buf = vec![0u8; 16 * 1024];
                loop {
                    let n = match sock.read(&mut buf).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => n,
                    };
                    if sock.write_all(&buf[..n]).await.is_err() {
                        return;
                    }
                }
            });
        }
    });
}

/// Hand-roll a SOCKS5 CONNECT and return the established stream.
async fn socks5_connect(proxy: SocketAddr, dst_ip: Ipv4Addr, dst_port: u16) -> TcpStream {
    let mut s = TcpStream::connect(proxy).await.unwrap();
    // Method negotiation: ver=5, 1 method, no-auth(0).
    s.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
    let mut hello = [0u8; 2];
    s.read_exact(&mut hello).await.unwrap();
    assert_eq!(hello, [0x05, 0x00]);

    // CONNECT request: ver=5, cmd=CONNECT(1), rsv=0, atyp=IPv4(1), addr(4), port(2).
    let mut req = vec![0x05, 0x01, 0x00, 0x01];
    req.extend_from_slice(&dst_ip.octets());
    req.extend_from_slice(&dst_port.to_be_bytes());
    s.write_all(&req).await.unwrap();

    let mut reply = [0u8; 10];
    s.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply[0], 0x05, "socks5 reply version");
    assert_eq!(reply[1], 0x00, "socks5 succeeded (rep=0x00)");
    s
}

fn make_config(socks_port: u16) -> Config {
    Config {
        log: LogConfig::default(),
        inbounds: vec![InboundConfig {
            tag: "socks-in".into(),
            listen: format!("127.0.0.1:{socks_port}"),
            kind: InboundKind::Socks(SocksInbound::default()),
            sniffing: Default::default(),
        }],
        outbounds: vec![OutboundConfig {
            tag: "direct".into(),
            kind: OutboundKind::Direct(DirectOutbound::default()),
        }],
        routing: RoutingConfig::default(),
        dns: DnsConfig::default(),
        mobile: MobileConfig::default(),
        control: None,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn socks5_direct_echo_roundtrip() {
    let socks_port = pick_port().await;
    let echo_port = pick_port().await;
    spawn_echo(echo_port).await;

    let cfg = make_config(socks_port);
    let engine = Engine::build(&cfg).expect("engine build");
    engine.run(&cfg).await.expect("engine run");

    // Give the listener a moment to actually be accepting.
    tokio::time::sleep(Duration::from_millis(50)).await;

    let mut s = socks5_connect(
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), socks_port),
        Ipv4Addr::LOCALHOST,
        echo_port,
    )
    .await;

    let payload = b"hello-mirage-beta-roundtrip";
    s.write_all(payload).await.unwrap();
    let mut echoed = vec![0u8; payload.len()];
    s.read_exact(&mut echoed).await.unwrap();
    assert_eq!(&echoed, payload);

    // Drop the client side; the engine's bidirectional pump should drain.
    drop(s);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn socks5_handles_unreachable_destination_cleanly() {
    let socks_port = pick_port().await;
    let cfg = make_config(socks_port);
    let engine = Engine::build(&cfg).expect("engine build");
    engine.run(&cfg).await.expect("engine run");
    tokio::time::sleep(Duration::from_millis(50)).await;

    let proxy = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), socks_port);
    let mut s = TcpStream::connect(proxy).await.unwrap();
    s.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
    let mut hello = [0u8; 2];
    s.read_exact(&mut hello).await.unwrap();
    assert_eq!(hello, [0x05, 0x00]);

    // 127.0.0.1:1 is reserved → connect refused.
    let mut req = vec![0x05, 0x01, 0x00, 0x01];
    req.extend_from_slice(&Ipv4Addr::LOCALHOST.octets());
    req.extend_from_slice(&1u16.to_be_bytes());
    s.write_all(&req).await.unwrap();

    let mut reply = [0u8; 10];
    s.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply[0], 0x05);
    // Engine should reply with a non-zero error code (0x05 = connection refused).
    assert_ne!(reply[1], 0x00, "engine should signal CONNECT failure");
}
