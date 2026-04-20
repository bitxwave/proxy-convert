//! Template command module

use crate::core::error::{ConvertError, Result};
use tracing::info;

/// Handle template generation command
pub async fn handle_template(
    template_cmd: &crate::commands::cli::Commands,
    _config: &crate::core::config::AppConfig,
    registry: &crate::protocols::ProtocolRegistry,
) -> Result<()> {
    // Extract Template command args
    let (output, protocol) = match template_cmd {
        crate::commands::cli::Commands::Template { output, protocol } => (output, protocol),
        _ => {
            return Err(ConvertError::ConfigValidationError(
                "Expected Template command".to_string(),
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
    let default_ext = format.config_ext();
    let template_content = format.default_template();

    info!(
        "Starting template generation for protocol: {}",
        protocol_name
    );

    // Output path
    let output_path = if let Some(path) = output {
        path.to_string_lossy().to_string()
    } else {
        format!("template.{}", default_ext)
    };

    // Write template
    std::fs::write(&output_path, &template_content).map_err(|e| ConvertError::IoError(e))?;

    info!("Template generated: {}", output_path);
    info!("Protocol: {}", protocol_name);
    Ok(())
}
