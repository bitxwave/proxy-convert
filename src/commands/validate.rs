//! Validate command module

use crate::commands::cli::ValidateArgs;
use crate::core::config::AppConfig;
use crate::core::error::{ConvertError, Result};
use crate::protocols::ProtocolRegistry;
use tracing::info;

/// Handle validate command
pub async fn handle_validate(
    args: &ValidateArgs,
    _config: &AppConfig,
    registry: &ProtocolRegistry,
) -> Result<()> {
    let format = registry
        .get_format(&args.protocol.to_lowercase())
        .ok_or_else(|| {
            ConvertError::ConfigValidationError(format!(
                "Unsupported protocol: {}. Supported: singbox, clash, v2ray",
                args.protocol
            ))
        })?;

    let protocol_name = format.name();
    let file_path = args.file.to_string_lossy();
    info!("Validating configuration file: {}", file_path);
    info!("Protocol: {}", protocol_name);

    if !args.file.exists() {
        return Err(ConvertError::file_not_found(&file_path));
    }

    let content = std::fs::read_to_string(&args.file)?;
    format.validate(&content)?;

    info!("Validation passed: {} (protocol: {})", file_path, protocol_name);
    Ok(())
}
