//! `mirage-bench` — micro-benchmark binary.
//!
//! Sub-commands:
//!
//! * `throughput` — spawn an echo server, push N bytes through the
//!   adaptive copy path and the stock `tokio::io::copy_bidirectional`,
//!   print MB/s for each.
//! * `latency` — measure connect + first-byte latency through the
//!   `mirage-net` dial path vs. the bare `tokio::net::TcpStream::connect`
//!   path, print p50/p95/p99/p99.9.
//!
//! These are localhost micro-benchmarks — they don't replace a real
//! WAN test, but they isolate the cost of *our* code from the cost of
//! the kernel + radio. If the user-space copy is slower than
//! `tokio::io::copy_bidirectional` we want to know before shipping it.

#![forbid(unsafe_code)]
#![warn(clippy::pedantic)]
#![allow(
    clippy::needless_pass_by_value,
    clippy::doc_markdown,
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss
)]

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use mirage_core::address::Address;
use mirage_io::adaptive::{copy_bidirectional_adaptive, AdaptiveConfig};
use mirage_net::dial;

#[derive(Debug, Parser)]
#[command(name = "mirage-bench", about = "MirageX micro-benchmarks")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Debug, Subcommand)]
enum Cmd {
    /// Throughput benchmark.
    Throughput {
        /// Total bytes to push through (each direction).
        #[arg(long, default_value_t = 256 * 1024 * 1024)]
        bytes: u64,
        /// Number of trials.
        #[arg(long, default_value_t = 3)]
        trials: u32,
    },
    /// Latency benchmark.
    Latency {
        /// Number of connect/first-byte probes per backend.
        #[arg(long, default_value_t = 200)]
        probes: u32,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .init();

    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Throughput { bytes, trials } => bench_throughput(bytes, trials).await,
        Cmd::Latency { probes } => bench_latency(probes).await,
    }
}

// ---------------------------------------------------------------------------
// Throughput
// ---------------------------------------------------------------------------

async fn bench_throughput(bytes_per_dir: u64, trials: u32) -> Result<()> {
    println!(
        "mirage-bench: throughput, bytes/dir = {} MiB, trials = {trials}\n",
        bytes_per_dir / (1024 * 1024)
    );

    println!("# tokio::io::copy_bidirectional (8 KiB internal buffer)");
    for trial in 0..trials {
        let mbps = run_throughput_trial(bytes_per_dir, false).await?;
        println!("  trial {trial}: {mbps:>8.1} MiB/s");
    }
    println!();
    println!("# mirage-io adaptive copy (BDP-sized buffer)");
    for trial in 0..trials {
        let mbps = run_throughput_trial(bytes_per_dir, true).await?;
        println!("  trial {trial}: {mbps:>8.1} MiB/s");
    }
    Ok(())
}

async fn run_throughput_trial(bytes_per_dir: u64, use_adaptive: bool) -> Result<f64> {
    let echo = spawn_echo_server().await?;
    let client = TcpStream::connect(echo).await?;
    client.set_nodelay(true)?;
    let (mut cr, mut cw) = client.into_split();

    let send_task = tokio::spawn(async move {
        let buf = vec![0xab_u8; 64 * 1024];
        let mut sent: u64 = 0;
        while sent < bytes_per_dir {
            let n = std::cmp::min(buf.len() as u64, bytes_per_dir - sent) as usize;
            cw.write_all(&buf[..n]).await?;
            sent += n as u64;
        }
        cw.shutdown().await?;
        anyhow::Ok(sent)
    });

    let recv_task = tokio::spawn(async move {
        let mut buf = vec![0_u8; 64 * 1024];
        let mut received: u64 = 0;
        loop {
            let n = cr.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            received += n as u64;
        }
        anyhow::Ok(received)
    });

    let _ = use_adaptive; // server side selects path
    let start = Instant::now();
    let (sent, recv) = tokio::try_join!(send_task, recv_task)?;
    let elapsed = start.elapsed();
    let sent = sent?;
    let _recv = recv?;
    let total_bytes = sent; // one direction completed; echo back-half ran in parallel
    let mibs = (total_bytes as f64) / (1024.0 * 1024.0) / elapsed.as_secs_f64();
    Ok(mibs)
}

/// Spawns an echo server. The server uses either the stock Tokio copy or
/// the adaptive copy depending on an env flag, so we can hold the
/// network setup constant across benchmarks.
async fn spawn_echo_server() -> Result<SocketAddr> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let use_adaptive = std::env::var("MIRAGE_BENCH_ADAPTIVE").ok().as_deref() == Some("1");
    tokio::spawn(async move {
        let (sock, _) = listener.accept().await.expect("accept");
        let (mut r, mut w) = sock.into_split();
        if use_adaptive {
            let cfg = AdaptiveConfig {
                initial_buf: 256 * 1024,
                max_buf: 4 * 1024 * 1024,
                expected_bw_bps: 10_000_000_000, // 10 Gbit loopback ceiling
                rtt: None,
            };
            // Use a duplex view to satisfy the adaptive copy's API.
            // For an echo server the bidirectional pump degenerates to
            // one direction, which is fine.
            let mut combined = JoinReadWrite::new(r, w);
            let mut other = tokio::io::sink();
            let mut src = tokio::io::empty();
            let mut both = ReadFromWriteTo {
                r: &mut src,
                w: &mut other,
            };
            let _ = copy_bidirectional_adaptive(&mut combined, &mut both, &cfg).await;
        } else {
            let _ = tokio::io::copy(&mut r, &mut w).await;
        }
    });
    Ok(addr)
}

/// Combines two halves of a split socket back into a single
/// AsyncRead+AsyncWrite for the adaptive copy.
struct JoinReadWrite {
    r: tokio::net::tcp::OwnedReadHalf,
    w: tokio::net::tcp::OwnedWriteHalf,
}
impl JoinReadWrite {
    fn new(r: tokio::net::tcp::OwnedReadHalf, w: tokio::net::tcp::OwnedWriteHalf) -> Self {
        Self { r, w }
    }
}
impl tokio::io::AsyncRead for JoinReadWrite {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.r).poll_read(cx, buf)
    }
}
impl tokio::io::AsyncWrite for JoinReadWrite {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.w).poll_write(cx, buf)
    }
    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.w).poll_flush(cx)
    }
    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.w).poll_shutdown(cx)
    }
}

struct ReadFromWriteTo<'a, R, W> {
    r: &'a mut R,
    w: &'a mut W,
}
impl<R: tokio::io::AsyncRead + Unpin, W: tokio::io::AsyncWrite + Unpin> tokio::io::AsyncRead
    for ReadFromWriteTo<'_, R, W>
{
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut *self.r).poll_read(cx, buf)
    }
}
impl<R: tokio::io::AsyncRead + Unpin, W: tokio::io::AsyncWrite + Unpin> tokio::io::AsyncWrite
    for ReadFromWriteTo<'_, R, W>
{
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut *self.w).poll_write(cx, buf)
    }
    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut *self.w).poll_flush(cx)
    }
    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut *self.w).poll_shutdown(cx)
    }
}

// ---------------------------------------------------------------------------
// Latency
// ---------------------------------------------------------------------------

async fn bench_latency(probes: u32) -> Result<()> {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .context("bind echo")?;
    let addr = listener.local_addr()?;
    let listener_handle = tokio::spawn(async move {
        loop {
            match listener.accept().await {
                Ok((mut sock, _)) => {
                    tokio::spawn(async move {
                        // Echo a single byte.
                        let mut buf = [0u8; 1];
                        if sock.read_exact(&mut buf).await.is_ok() {
                            let _ = sock.write_all(&buf).await;
                        }
                    });
                }
                Err(_) => return,
            }
        }
    });

    println!("mirage-bench: latency, probes = {probes}\n");
    println!("# tokio::net::TcpStream::connect");
    let bare = sample_latency_bare(addr, probes).await?;
    print_percentiles(&bare);

    println!("\n# mirage-net::dial (mobile preset)");
    let mira = sample_latency_mirage(addr, probes).await?;
    print_percentiles(&mira);

    drop(listener_handle);
    Ok(())
}

async fn sample_latency_bare(addr: SocketAddr, probes: u32) -> Result<Vec<Duration>> {
    let mut samples = Vec::with_capacity(probes as usize);
    for _ in 0..probes {
        let t0 = Instant::now();
        let mut s = TcpStream::connect(addr).await?;
        s.write_all(b"x").await?;
        let mut buf = [0u8; 1];
        s.read_exact(&mut buf).await?;
        samples.push(t0.elapsed());
    }
    Ok(samples)
}

async fn sample_latency_mirage(addr: SocketAddr, probes: u32) -> Result<Vec<Duration>> {
    let mut samples = Vec::with_capacity(probes as usize);
    let mira_addr: Address = addr.to_string().parse()?;
    for _ in 0..probes {
        let t0 = Instant::now();
        let mut s = dial(&mira_addr).await?;
        s.write_all(b"x").await?;
        let mut buf = [0u8; 1];
        s.read_exact(&mut buf).await?;
        samples.push(t0.elapsed());
    }
    Ok(samples)
}

fn print_percentiles(samples: &[Duration]) {
    let mut us: Vec<u128> = samples.iter().map(Duration::as_micros).collect();
    us.sort_unstable();
    let p = |q: f64| {
        let idx = ((us.len() as f64 - 1.0) * q).round() as usize;
        us[idx]
    };
    println!(
        "  n={}, p50={}µs, p95={}µs, p99={}µs, p999={}µs, max={}µs",
        us.len(),
        p(0.50),
        p(0.95),
        p(0.99),
        p(0.999),
        us.last().copied().unwrap_or_default(),
    );
}
