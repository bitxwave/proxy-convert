//! Validate command module

use crate::core::config::AppConfig;
use crate::protocols::{clash, singbox, v2ray, ProtocolRegistry};
use crate::core::error::{ConvertError, Result};
use tracing::info;

/// Handle validate command
pub async fn handle_validate(
    validate_cmd: &crate::commands::cli::Commands,
    _config: &AppConfig,
    _registry: &ProtocolRegistry,
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

    // Resolve protocol
    let protocol_lower = protocol.to_lowercase();
    let protocol_name = match protocol_lower.as_str() {
        "singbox" | "sing-box" => singbox::PROTOCOL_NAME,
        "clash" => clash::PROTOCOL_NAME,
        "v2ray" => v2ray::PROTOCOL_NAME,
        _ => {
            return Err(ConvertError::ConfigValidationError(format!(
                "Unsupported protocol: {}. Supported: singbox, clash, v2ray",
                protocol
            )))
        }
    };

    let file_path = file.to_string_lossy();
    info!("Validating configuration file: {}", file_path);
    info!("Protocol: {}", protocol_name);

    // Check file exists
    if !file.exists() {
        return Err(ConvertError::file_not_found(&file_path));
    }

    // Read config file
    let content = std::fs::read_to_string(&*file_path).map_err(|e| ConvertError::IoError(e))?;

    // Validate by protocol
    match protocol_name {
        singbox::PROTOCOL_NAME => validate_singbox_config(&content)?,
        clash::PROTOCOL_NAME => validate_clash_config(&content)?,
        v2ray::PROTOCOL_NAME => validate_v2ray_config(&content)?,
        _ => unreachable!(),
    }

    info!("Validation passed: {} (protocol: {})", file_path, protocol_name);
    Ok(())
}

/// Validate Sing-box configuration
fn validate_singbox_config(content: &str) -> Result<()> {
    // Try to parse as JSON
    let config: serde_json::Value =
        serde_json::from_str(content).map_err(|e| ConvertError::JsonParseError(e))?;

    // Check required fields for Sing-box
    if config.get("outbounds").is_none() {
        return Err(ConvertError::ConfigValidationError(
            "Missing required field 'outbounds' for Sing-box config".to_string(),
        ));
    }

    info!("Sing-box config structure is valid");
    Ok(())
}

/// Validate Clash configuration
fn validate_clash_config(content: &str) -> Result<()> {
    // Try to parse as YAML or JSON
    let config: serde_json::Value = serde_yaml::from_str(content)
        .map_err(|e| ConvertError::ConfigValidationError(format!("YAML parse error: {}", e)))?;

    // Check required fields for Clash
    if config.get("proxies").is_none() && config.get("proxy-providers").is_none() {
        return Err(ConvertError::ConfigValidationError(
            "Missing required field 'proxies' or 'proxy-providers' for Clash config".to_string(),
        ));
    }

    info!("Clash config structure is valid");
    Ok(())
}

/// Validate V2Ray configuration
fn validate_v2ray_config(content: &str) -> Result<()> {
    // Try to parse as JSON
    let config: serde_json::Value =
        serde_json::from_str(content).map_err(|e| ConvertError::JsonParseError(e))?;

    // Check required fields for V2Ray
    if config.get("outbounds").is_none() {
        return Err(ConvertError::ConfigValidationError(
            "Missing required field 'outbounds' for V2Ray config".to_string(),
        ));
    }

    info!("V2Ray config structure is valid");
    Ok(())
}
