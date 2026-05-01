//! Template command module

use crate::commands::cli::TemplateArgs;
use crate::core::config::AppConfig;
use crate::core::error::{ConvertError, Result};
use crate::protocols::ProtocolRegistry;
use tracing::info;

/// Handle template generation command
pub async fn handle_template(
    args: &TemplateArgs,
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
    let default_ext = format.config_ext();
    let template_content = format.default_template();

    info!("Starting template generation for protocol: {}", protocol_name);

    let output_path = args
        .output
        .as_ref()
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_else(|| format!("template.{}", default_ext));

    std::fs::write(&output_path, &template_content)?;

    info!("Template generated: {}", output_path);
    info!("Protocol: {}", protocol_name);
    Ok(())
}
