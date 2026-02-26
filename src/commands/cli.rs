use clap::{Parser, Subcommand, ValueEnum};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(
    name = "proxy-convert",
    author = "Messica <messica@example.com>",
    version = "2.0.0",
    about = "A modern tool for converting proxy configuration",
    long_about = "A powerful tool for converting proxy configuration. Supports multiple protocol conversions, template customization, rule filtering and other features."
)]
pub struct Cli {
    /// Configuration file path. If not specified, will search in default locations:
    /// 1. ./config.yaml or ./config.yml (current directory)
    /// 2. ~/.config/proxy-convert/config.yaml (Linux/macOS) or %APPDATA%/proxy-convert/config.yaml (Windows)
    #[arg(short, long, global = true, value_name = "PATH")]
    pub config: Option<PathBuf>,

    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Convert subscription configuration
    Convert {
        /// Input sources: <path|url>?type=clash&name=...&flag=... (type required in query)
        #[arg(long = "source", value_name = "SOURCE")]
        sources: Vec<String>,

        /// Template file path
        #[arg(short, long, value_name = "PATH")]
        template: Option<PathBuf>,

        /// Output file path
        #[arg(short, long, value_name = "PATH")]
        output: Option<PathBuf>,

        /// Target output protocol (sing-box, clash, v2ray).
        /// The output format is determined by the protocol:
        /// - sing-box: JSON only
        /// - clash: YAML only
        /// - v2ray: JSON only
        #[arg(long = "output-protocol", value_name = "PROTOCOL")]
        output_protocol: Option<String>,

        /// Log level
        #[arg(short, long, value_enum, default_value_t = LogLevel::Info)]
        log_level: LogLevel,

        /// Whether to show detailed information
        #[arg(short, long)]
        verbose: bool,

        /// HTTP request timeout in seconds
        #[arg(long, value_name = "SECONDS")]
        timeout: Option<u64>,
    },

    /// Validate configuration file
    Validate {
        /// Configuration file path to validate
        #[arg(value_name = "PATH")]
        file: PathBuf,

        /// Target protocol (sing-box, clash, v2ray). Default: sing-box
        #[arg(short, long, value_name = "PROTOCOL", default_value = "singbox")]
        protocol: String,
    },

    /// Generate default template
    Template {
        /// Output path
        #[arg(short, long, value_name = "PATH")]
        output: Option<PathBuf>,

        /// Target protocol (sing-box, clash, v2ray). Default: sing-box
        #[arg(short, long, value_name = "PROTOCOL", default_value = "singbox")]
        protocol: String,
    },

    /// Display version information
    Version,
}

#[derive(ValueEnum, Clone, Debug)]
pub enum OutputFormat {
    /// JSON format
    Json,
    /// YAML format
    Yaml,
}

#[derive(ValueEnum, Clone, Copy, Debug)]
pub enum LogLevel {
    /// Error information
    Error,
    /// Warning information
    Warn,
    /// General information
    Info,
    /// Debug information
    Debug,
    /// Trace information
    Trace,
}

impl From<LogLevel> for tracing::Level {
    fn from(level: LogLevel) -> Self {
        match level {
            LogLevel::Error => tracing::Level::ERROR,
            LogLevel::Warn => tracing::Level::WARN,
            LogLevel::Info => tracing::Level::INFO,
            LogLevel::Debug => tracing::Level::DEBUG,
            LogLevel::Trace => tracing::Level::TRACE,
        }
    }
}
