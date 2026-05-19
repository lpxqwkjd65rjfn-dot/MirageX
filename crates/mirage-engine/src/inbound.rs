//! Inbound implementations. Currently only SOCKS5 (TCP CONNECT) is wired up;
//! the HTTP CONNECT and TUN inbounds will follow.

use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::{debug, error, info, warn};

use mirage_config::inbound::InboundConfig;
use mirage_config::mobile::MobileConfig;
use mirage_core::address::{Address, Host};
use mirage_core::error::{Error, Result};
use mirage_core::network::Network;
use mirage_io::adaptive::{copy_bidirectional_adaptive, AdaptiveConfig};

use crate::dispatcher::{Dispatcher, Session};
use crate::net::options_from_mobile;

/// Spawn a per-inbound listener task. Returns once the listener is bound.
pub async fn spawn(
    cfg: InboundConfig,
    dispatcher: Arc<Dispatcher>,
    mobile: Arc<MobileConfig>,
) -> Result<()> {
    match &cfg.kind {
        mirage_config::inbound::InboundKind::Socks(_) => spawn_socks(cfg, dispatcher, mobile).await,
        other => Err(Error::Config(format!(
            "inbound kind not yet implemented: {other:?}"
        ))),
    }
}

async fn spawn_socks(
    cfg: InboundConfig,
    dispatcher: Arc<Dispatcher>,
    mobile: Arc<MobileConfig>,
) -> Result<()> {
    let opts = options_from_mobile(&mobile);
    let listen_addr = cfg.listen.parse::<std::net::SocketAddr>().map_err(|e| {
        Error::Config(format!(
            "inbound `{}`: bad listen `{}`: {e}",
            cfg.tag, cfg.listen
        ))
    })?;
    let listener =
        mirage_net::listen::listen_with(listen_addr, &opts, mirage_net::listen::DEFAULT_BACKLOG)
            .await
            .map_err(Error::Io)?;
    info!(listen = %cfg.listen, tag = %cfg.tag, "socks inbound started");
    let cfg = Arc::new(cfg);
    tokio::spawn(async move {
        loop {
            match listener.accept().await {
                Ok((sock, peer)) => {
                    // Apply the same post-connect socket policy (keep-alive,
                    // user_timeout, …) to accepted client sockets too.
                    opts.apply_post(&sock);
                    let dispatcher = dispatcher.clone();
                    let cfg = cfg.clone();
                    let mobile = mobile.clone();
                    tokio::spawn(async move {
                        if let Err(e) = handle_socks(sock, peer, cfg, dispatcher, mobile).await {
                            warn!(?peer, "socks: connection ended with error: {e}");
                        }
                    });
                }
                Err(e) => {
                    error!("socks: accept failed: {e}");
                    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                }
            }
        }
    });
    Ok(())
}

async fn handle_socks(
    mut sock: tokio::net::TcpStream,
    peer: std::net::SocketAddr,
    cfg: Arc<InboundConfig>,
    dispatcher: Arc<Dispatcher>,
    mobile: Arc<MobileConfig>,
) -> Result<()> {
    // -- Handshake -------------------------------------------------------
    let mut head = [0u8; 2];
    sock.read_exact(&mut head).await.map_err(Error::Io)?;
    if head[0] != 0x05 {
        return Err(Error::Protocol("not SOCKS5".into()));
    }
    let mut methods = vec![0u8; head[1] as usize];
    sock.read_exact(&mut methods).await.map_err(Error::Io)?;
    // We only advertise "no auth" (0x00) in this MVP. User/pass arrives shortly.
    sock.write_all(&[0x05, 0x00]).await.map_err(Error::Io)?;

    // -- Request ---------------------------------------------------------
    let mut req = [0u8; 4];
    sock.read_exact(&mut req).await.map_err(Error::Io)?;
    if req[0] != 0x05 {
        return Err(Error::Protocol("not SOCKS5 (req)".into()));
    }
    let cmd = req[1];
    let atyp = req[3];
    let dest = match atyp {
        0x01 => {
            let mut o = [0u8; 4];
            sock.read_exact(&mut o).await.map_err(Error::Io)?;
            let mut port_buf = [0u8; 2];
            sock.read_exact(&mut port_buf).await.map_err(Error::Io)?;
            Address {
                host: Host::Ip(std::net::IpAddr::V4(o.into())),
                port: u16::from_be_bytes(port_buf),
            }
        }
        0x03 => {
            let mut lb = [0u8; 1];
            sock.read_exact(&mut lb).await.map_err(Error::Io)?;
            let mut name = vec![0u8; lb[0] as usize];
            sock.read_exact(&mut name).await.map_err(Error::Io)?;
            let mut port_buf = [0u8; 2];
            sock.read_exact(&mut port_buf).await.map_err(Error::Io)?;
            Address {
                host: Host::Domain(
                    String::from_utf8(name).map_err(|_| Error::Protocol("bad domain".into()))?,
                ),
                port: u16::from_be_bytes(port_buf),
            }
        }
        0x04 => {
            let mut o = [0u8; 16];
            sock.read_exact(&mut o).await.map_err(Error::Io)?;
            let mut port_buf = [0u8; 2];
            sock.read_exact(&mut port_buf).await.map_err(Error::Io)?;
            Address {
                host: Host::Ip(std::net::IpAddr::V6(o.into())),
                port: u16::from_be_bytes(port_buf),
            }
        }
        _ => return Err(Error::Protocol(format!("unknown atyp: {atyp}"))),
    };
    if cmd != 0x01 {
        // 0x07 = command not supported
        sock.write_all(&[0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
            .await
            .map_err(Error::Io)?;
        return Err(Error::Protocol(format!("unsupported socks command: {cmd}")));
    }

    debug!(?peer, %dest, "socks: routing");
    let session = Session {
        inbound_tag: cfg.tag.clone(),
        destination: dest,
        network: Network::Tcp,
    };
    let outbound = dispatcher.select(&session)?;
    let upstream = match outbound.dial(&session).await {
        Ok(s) => s,
        Err(e) => {
            sock.write_all(&[0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await
                .map_err(Error::Io)?;
            return Err(e);
        }
    };

    // Success reply.
    sock.write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
        .await
        .map_err(Error::Io)?;

    // BDP-adaptive bidirectional pump. The expected bandwidth comes from
    // a conservative "cellular default" until the engine learns a real
    // per-flow bandwidth estimate; the initial buffer is much larger than
    // tokio's default 8 KiB so even short flows benefit on high-RTT paths.
    let adaptive = AdaptiveConfig {
        initial_buf: 256 * 1024,
        max_buf: 4 * 1024 * 1024,
        expected_bw_bps: bw_hint_for(&mobile),
        rtt: None,
    };
    let mut upstream = upstream;
    copy_bidirectional_adaptive(&mut sock, &mut *upstream, &adaptive)
        .await
        .map_err(Error::Io)?;
    Ok(())
}

/// Pick an expected-bandwidth hint based on the mobile profile.
/// 100 Mbit for aggressive, 50 Mbit for balanced, 25 Mbit for conservative.
fn bw_hint_for(m: &MobileConfig) -> u64 {
    use mirage_config::mobile::RetransmitProfile;
    if !m.enabled {
        return 0;
    }
    match m.retransmit {
        RetransmitProfile::Conservative => 25_000_000,
        RetransmitProfile::Balanced => 50_000_000,
        RetransmitProfile::Aggressive => 100_000_000,
    }
}

// `Outbound` is a trait — explicit import so `outbound.dial(...)` resolves.
use crate::dispatcher::Outbound as _;
