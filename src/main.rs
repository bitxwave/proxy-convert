//! Proxy Configuration Converter Main Program
//!
//! A modern, extensible tool for converting between different proxy configuration formats.
//! Supports Clash, Sing-box, V2Ray and other formats.

use proxy_convert::commands::cli::{Cli, Commands};
use proxy_convert::commands::{convert, template, validate, version};
use proxy_convert::core::error;
use proxy_convert::core::{config::AppConfig, logging};
use clap::Parser;
use tracing::Level;

#[tokio::main]
async fn main() {
    if let Err(e) = run().await {
        eprintln!("\x1b[31mError:\x1b[0m {}", e.format_error());
        std::process::exit(1);
    }
}

async fn run() -> error::Result<()> {
    let cli = Cli::parse();

    // Version is standalone — no config load, no logging setup needed.
    if matches!(cli.command, Commands::Version) {
        version::handle_version();
        return Ok(());
    }

    let config_path = cli.config.as_ref().and_then(|p| p.to_str());
    let mut config = AppConfig::load_from_path(config_path)?;

    if let Commands::Convert(args) = &cli.command {
        config.merge_convert_args(args);
    }

    let log_level = match config.log_level.to_lowercase().as_str() {
        "error" => Level::ERROR,
        "warn" => Level::WARN,
        "debug" => Level::DEBUG,
        "trace" => Level::TRACE,
        _ => Level::INFO,
    };
    logging::init_logging(log_level)?;

    let registry = proxy_convert::protocols::ProtocolRegistry::init();

    match cli.command {
        Commands::Convert(args) => convert::handle_convert(&args, &config, &registry).await,
        Commands::Validate(args) => validate::handle_validate(&args, &config, &registry).await,
        Commands::Template(args) => template::handle_template(&args, &config, &registry).await,
        Commands::Version => unreachable!("handled above"),
    }
}
