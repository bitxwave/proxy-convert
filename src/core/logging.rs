//! Logging module

use crate::utils::error::Result;
use tracing::{info, Level};
use tracing_subscriber::EnvFilter;

/// Initialize logging system
pub fn init_logging(log_level: Level) -> Result<()> {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(format!("proxy_convert={}", log_level.as_str())));

    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .with_thread_ids(false)
        .with_thread_names(false)
        .init();

    info!("Logging system initialized, level: {}", log_level);
    Ok(())
}
