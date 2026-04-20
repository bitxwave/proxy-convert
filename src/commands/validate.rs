//! Validate command module

use crate::core::config::AppConfig;
use crate::protocols::ProtocolRegistry;
use crate::core::error::{ConvertError, Result};
use tracing::info;

/// Handle validate command
pub async fn handle_validate(
    validate_cmd: &crate::commands::cli::Commands,
    _config: &AppConfig,
    registry: &ProtocolRegistry,
) -> Result<()> {
    // Extract Validate command args
    let (file, protocol) = match validate_cmd {
        crate::commands::cli::Commands::Validate { file, protocol } => (file, protocol),
        _ => {
            return Err(ConvertError::ConfigValidationError(
                "Expected Validate command".to_string(),
            ))
        }
    };

    // Resolve protocol via registry
    let protocol_lower = protocol.to_lowercase();
    let format = registry.get_format(&protocol_lower).ok_or_else(|| {
        ConvertError::ConfigValidationError(format!(
            "Unsupported protocol: {}. Supported: singbox, clash, v2ray",
            protocol
        ))
    })?;

    let protocol_name = format.name();
    let file_path = file.to_string_lossy();
    info!("Validating configuration file: {}", file_path);
    info!("Protocol: {}", protocol_name);

    // Check file exists
    if !file.exists() {
        return Err(ConvertError::file_not_found(&file_path));
    }

    // Read config file
    let content = std::fs::read_to_string(&*file_path).map_err(|e| ConvertError::IoError(e))?;

    // Validate via the ProtocolFormat trait
    format.validate(&content)?;

    info!("Validation passed: {} (protocol: {})", file_path, protocol_name);
    Ok(())
}
