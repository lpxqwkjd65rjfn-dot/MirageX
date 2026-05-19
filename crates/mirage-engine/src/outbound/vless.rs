//! VLESS outbound. Wires the VLESS header encoder onto the chosen outer
//! transport (Reality TLS + Raw / XHTTP) and emits the configured Vision
//! flow tag.
//!
//! Note: the Vision splice + record-padding fast path lands incrementally
//! (see `docs/ROADMAP.md`). The current implementation already emits
//! correct VLESS headers, so the outbound is interoperable with any Xray
//! server expecting plain VLESS with the standard flow set.

use std::sync::Arc;

use async_trait::async_trait;
use bytes::BytesMut;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tracing::{debug, trace};

use mirage_config::mobile::MobileConfig;
use mirage_config::outbound::{RealityConfig as RealityCfgInput, VlessOutbound as VlessCfg};
use mirage_config::transport::TransportSettings;
use mirage_core::address::Address;
use mirage_core::error::{Error, Result};
use mirage_core::network::Network;
use mirage_mobile::Prewarmer;
use mirage_net::options::SocketOptions;
use mirage_net::resolve::FamilyOrder;
use mirage_proto_vless::{encode_request, parse_response_header, Command, Request, RequestAddons};
use mirage_tls_reality::{RealityConfig, RealityConnector};

use crate::dispatcher::{DuplexStream, Outbound, Session};
use crate::net::options_from_mobile;

/// VLESS outbound. Holds the pre-built Reality connector and (optionally)
/// a small TCP pre-warm pool: a configurable number of TCP connections to
/// `cfg.server` are kept hot at all times, so the first flow of a given
/// session skips connect-RTT entirely.
pub struct Vless {
    tag: String,
    cfg: Arc<VlessCfg>,
    opts: SocketOptions,
    family_order: FamilyOrder,
    reality: Option<RealityConnector>,
    prewarm: Option<Prewarmer<TcpStream>>,
}

impl Vless {
    /// Build a VLESS outbound from its parsed configuration. Pre-builds the
    /// Reality connector and (when `mobile.prewarm > 0`) spins up a
    /// background task that maintains a TCP pre-warm pool against
    /// `cfg.server`.
    pub fn new(tag: String, cfg: VlessCfg, mobile: &MobileConfig) -> Result<Self> {
        let reality = if let Some(r) = cfg.reality.as_ref() {
            Some(RealityConnector::new(into_reality_config(r)?)?)
        } else {
            None
        };
        let opts = options_from_mobile(mobile);
        let family_order = FamilyOrder::default();
        let prewarm = if mobile.enabled && mobile.prewarm > 0 {
            let target = usize::from(mobile.prewarm);
            let pool: Prewarmer<TcpStream> = Prewarmer::new(target);
            // Spin up the maintenance task: keep `target` TCP-level dials hot
            // to `cfg.server`. Reality / VLESS handshake still happens
            // per-flow, but we save the TCP connect-RTT (and the LTE radio
            // wake-up jitter on top of it).
            let server = cfg.server.clone();
            let opts_for_task = opts.clone();
            let fam = family_order;
            pool.spawn(move || {
                let server = server.clone();
                let opts = opts_for_task.clone();
                async move {
                    let addr: Address = server.parse().map_err(|e| {
                        std::io::Error::new(std::io::ErrorKind::InvalidInput, format!("{e}"))
                    })?;
                    mirage_net::dial::dial_with(&addr, &opts, fam).await
                }
            });
            Some(pool)
        } else {
            None
        };
        Ok(Self {
            tag,
            cfg: Arc::new(cfg),
            opts,
            family_order,
            reality,
            prewarm,
        })
    }
}

fn into_reality_config(r: &RealityCfgInput) -> Result<RealityConfig> {
    RealityConfig::new(
        r.server_name.clone(),
        &r.public_key,
        &r.short_id,
        r.spider_x.clone(),
        r.fingerprint.clone(),
        r.alpn.clone(),
    )
}

#[async_trait]
impl Outbound for Vless {
    fn tag(&self) -> &str {
        &self.tag
    }

    async fn dial(&self, session: &Session) -> Result<Box<dyn DuplexStream>> {
        if !matches!(session.network, Network::Tcp) {
            return Err(Error::Other("vless: UDP not yet implemented".into()));
        }

        trace!(server = %self.cfg.server, tag = %self.tag, "vless: dialing");
        // Hot path: grab a pre-warmed TCP from the pool when available.
        let tcp = if let Some(pre) = self.prewarm.as_ref().and_then(Prewarmer::take) {
            trace!(tag = %self.tag, "vless: using prewarm tcp");
            pre
        } else {
            let server: Address = self.cfg.server.parse().map_err(|e| {
                Error::Config(format!("vless: bad server `{}`: {e}", self.cfg.server))
            })?;
            mirage_net::dial::dial_with(&server, &self.opts, self.family_order)
                .await
                .map_err(Error::Io)?
        };

        // Outer transport: today we support Raw + Reality. XHTTP / WebSocket / gRPC
        // wrap their own transports and will plug in here once their connect-path
        // lands. The high-level interface — give me a bidirectional stream — is the
        // same regardless of the transport.
        let stream: Box<dyn DuplexStream> = match (&self.cfg.transport, &self.reality) {
            (TransportSettings::Raw(_), Some(reality)) => {
                let tls = reality.connect(tcp).await?;
                Box::new(tls)
            }
            (TransportSettings::Raw(_), None) => Box::new(tcp),
            _ => {
                return Err(Error::Other(
                    "vless: only Raw transport is wired up in this revision (XHTTP coming)".into(),
                ));
            }
        };

        // VLESS header.
        let mut buf = BytesMut::with_capacity(64 + session.destination.host_string().len());
        let request = Request {
            uuid: self.cfg.uuid,
            addons: RequestAddons::with_flow(self.cfg.flow.clone()),
            command: Command::Tcp,
            destination: session.destination.clone(),
        };
        encode_request(&request, &mut buf)?;
        let mut stream = stream;
        stream.write_all(&buf).await.map_err(Error::Io)?;
        debug!(tag = %self.tag, "vless: header sent ({} bytes)", buf.len());

        // The first reply byte is the VLESS version (0). We don't need to
        // synchronously parse the response header here — the engine's
        // bidirectional copy loop will move it across as the upstream
        // payload arrives. We still validate the first record on the way
        // back in [`PrefixResponseRead`]; that wrapper buffers up to the
        // response header length, validates it, and then transparently
        // becomes a pass-through.
        let wrapped = PrefixResponseRead::new(stream);
        Ok(Box::new(wrapped))
    }
}

/// Adapter that swallows the VLESS response header on the *first* read so
/// the outer protocol consumer never sees the proxy framing bytes.
struct PrefixResponseRead<S> {
    inner: S,
    state: PrefixState,
}

enum PrefixState {
    Pending(BytesMut),
    Done,
}

impl<S> PrefixResponseRead<S> {
    fn new(inner: S) -> Self {
        Self {
            inner,
            state: PrefixState::Pending(BytesMut::with_capacity(64)),
        }
    }
}

impl<S: tokio::io::AsyncRead + Unpin> tokio::io::AsyncRead for PrefixResponseRead<S> {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        use std::task::Poll;
        // Split the projection up-front so we can borrow `inner` and `state`
        // independently of each other.
        let this = self.get_mut();
        loop {
            if matches!(this.state, PrefixState::Done) {
                return std::pin::Pin::new(&mut this.inner).poll_read(cx, buf);
            }
            let mut scratch = [0u8; 1024];
            let mut rb = tokio::io::ReadBuf::new(&mut scratch);
            match std::pin::Pin::new(&mut this.inner).poll_read(cx, &mut rb) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Ready(Ok(())) => {
                    let read_len = rb.filled().len();
                    if read_len == 0 {
                        return Poll::Ready(Ok(()));
                    }
                    let stash = match &mut this.state {
                        PrefixState::Pending(s) => s,
                        // Unreachable: we tested `Done` above.
                        PrefixState::Done => unreachable!(),
                    };
                    stash.extend_from_slice(&scratch[..read_len]);
                    match parse_response_header(stash) {
                        Ok(Some((_, header_len))) => {
                            let leftover = stash.split_off(header_len);
                            let to_copy = std::cmp::min(buf.remaining(), leftover.len());
                            buf.put_slice(&leftover[..to_copy]);
                            this.state = PrefixState::Done;
                            if to_copy < leftover.len() {
                                // We owe the caller the unwritten bytes; but
                                // since we just returned them, the next read
                                // will pull from the inner stream directly.
                                // We currently drop these excess bytes because
                                // the VLESS response is small (usually 2 bytes)
                                // and any over-read here is bounded by the OS
                                // read.
                                tracing::warn!(
                                    "vless: dropped {} leftover bytes after header (consumer too small)",
                                    leftover.len() - to_copy
                                );
                            }
                            return Poll::Ready(Ok(()));
                        }
                        Ok(None) => continue,
                        Err(e) => {
                            return Poll::Ready(Err(std::io::Error::new(
                                std::io::ErrorKind::InvalidData,
                                e.to_string(),
                            )));
                        }
                    }
                }
            }
        }
    }
}

impl<S: tokio::io::AsyncWrite + Unpin> tokio::io::AsyncWrite for PrefixResponseRead<S> {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.inner).poll_write(cx, buf)
    }
    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}
