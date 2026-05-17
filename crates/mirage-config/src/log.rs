//! Logging configuration.

use serde::{Deserialize, Serialize};

/// Logging configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct LogConfig {
    /// Minimum log level emitted by the engine.
    pub level: LogLevel,
    /// Whether to write logs in JSON or human-readable text.
    pub format: LogFormat,
    /// Optional log file path. When `None`, logs go to stderr.
    pub file: Option<String>,
    /// Whether to include source-file locations in each record (slightly slower).
    pub source_location: bool,
    /// Whether to include the active span ids in each record (useful for tracing
    /// long-lived flows through the engine).
    pub include_spans: bool,
}

impl Default for LogConfig {
    fn default() -> Self {
        Self {
            level: LogLevel::Info,
            format: LogFormat::Text,
            file: None,
            source_location: false,
            include_spans: true,
        }
    }
}

/// Severity threshold for the logger.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LogLevel {
    /// `trace` level — extremely chatty.
    Trace,
    /// `debug` level.
    Debug,
    /// `info` level — recommended default.
    Info,
    /// `warn` level.
    Warn,
    /// `error` level.
    Error,
}

/// Output format for the logger.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LogFormat {
    /// Plain text, ANSI-coloured on a TTY.
    Text,
    /// One JSON object per record. Suitable for ingestion by log aggregators.
    Json,
}
