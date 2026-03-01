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
    // Parse command line arguments
    let cli = Cli::parse();

    // Handle commands
    match cli.command {
        Commands::Version => {
            version::handle_version();
            Ok(())
        }
        _ => {
            // Load configuration from specified path or default locations
            let config_path = cli.config.as_ref().and_then(|p| p.to_str());
            let mut config = AppConfig::load_from_path(config_path)?;

            // Merge CLI parameters into config (CLI parameters take precedence)
            config.merge_cli_params(&cli.command)?;

            // Initialize logging system with config log level
            let log_level = match config.log_level.to_lowercase().as_str() {
                "error" => Level::ERROR,
                "warn" => Level::WARN,
                "debug" => Level::DEBUG,
                "trace" => Level::TRACE,
                _ => Level::INFO,
            };
            logging::init_logging(log_level)?;

            // Initialize protocol registry
            let registry = proxy_convert::protocols::ProtocolRegistry::init();

            // Handle other commands
            match cli.command {
                Commands::Convert { .. } => {
                    convert::handle_convert(&cli.command, &config, &registry).await
                }
                Commands::Validate { .. } => {
                    validate::handle_validate(&cli.command, &config, &registry).await
                }
                Commands::Template { .. } => {
                    template::handle_template(&cli.command, &config, &registry).await
                }
                Commands::Version => unreachable!(),
            }
        }
    }
}
