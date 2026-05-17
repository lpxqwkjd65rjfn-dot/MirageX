//! `miragex` — command-line entry point.
//!
//! Subcommands:
//!
//! * `miragex run -c config.toml`     — bring up the engine.
//! * `miragex check -c config.toml`   — parse + validate the configuration.
//! * `miragex gen-config`             — print a heavily-commented sample config.
//! * `miragex version`                — print the build version.

#![forbid(unsafe_code)]
#![warn(clippy::pedantic)]
#![allow(
    clippy::needless_pass_by_value,
    clippy::doc_markdown,
    clippy::must_use_candidate,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::unnecessary_wraps
)]

use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use tracing_subscriber::EnvFilter;

use mirage_config::{Config, LogFormat, LogLevel};
use mirage_engine::Engine;

const SAMPLE_CONFIG: &str = include_str!("../../../examples/client-reality-xhttp.toml");

#[derive(Debug, Parser)]
#[command(
    name = "miragex",
    version,
    about = "MirageX — performance-first Xray-compatible client"
)]
struct Cli {
    /// Override the log level (`trace`/`debug`/`info`/`warn`/`error`).
    #[arg(long, env = "MIRAGEX_LOG", global = true)]
    log: Option<String>,

    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Debug, Subcommand)]
enum Cmd {
    /// Bring up the engine using a config file.
    Run {
        /// Path to the configuration file (TOML or JSON).
        #[arg(short = 'c', long, default_value = "client.toml")]
        config: PathBuf,
    },
    /// Parse + validate a config file. Exit code 0 = OK.
    Check {
        /// Path to the configuration file.
        #[arg(short = 'c', long, default_value = "client.toml")]
        config: PathBuf,
    },
    /// Print a heavily-commented sample configuration to stdout.
    GenConfig,
    /// Print the build version.
    Version,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.cmd {
        Cmd::Version => {
            println!("miragex {}", env!("CARGO_PKG_VERSION"));
            return Ok(());
        }
        Cmd::GenConfig => {
            print!("{SAMPLE_CONFIG}");
            return Ok(());
        }
        Cmd::Check { config } => {
            init_logger("info", LogFormat::Text)?;
            let cfg = Config::load(&config)
                .with_context(|| format!("loading config from {}", config.display()))?;
            println!(
                "OK: {} inbounds, {} outbounds, {} routing rules",
                cfg.inbounds.len(),
                cfg.outbounds.len(),
                cfg.routing.rules.len()
            );
            return Ok(());
        }
        Cmd::Run { config } => {
            let cfg = Config::load(&config)
                .with_context(|| format!("loading config from {}", config.display()))?;
            let log_level = cli.log.as_deref().unwrap_or(match cfg.log.level {
                LogLevel::Trace => "trace",
                LogLevel::Debug => "debug",
                LogLevel::Info => "info",
                LogLevel::Warn => "warn",
                LogLevel::Error => "error",
            });
            init_logger(log_level, cfg.log.format)?;
            run_engine(cfg)?;
        }
    }
    Ok(())
}

fn init_logger(level: &str, format: LogFormat) -> Result<()> {
    let filter = EnvFilter::try_new(format!("{level},miragex={level}"))
        .unwrap_or_else(|_| EnvFilter::new("info"));
    let builder = tracing_subscriber::fmt().with_env_filter(filter);
    match format {
        LogFormat::Text => builder.init(),
        LogFormat::Json => builder.json().init(),
    }
    Ok(())
}

fn run_engine(cfg: Config) -> Result<()> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .thread_name("miragex-worker")
        .build()?;
    runtime.block_on(async move {
        let engine = Engine::build(&cfg)?;
        engine.run(&cfg).await?;
        tracing::info!("miragex: engine running. Ctrl-C to stop.");
        tokio::signal::ctrl_c().await?;
        tracing::info!("miragex: shutdown requested.");
        anyhow::Ok(())
    })
}
