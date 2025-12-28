//! Validate command module

use crate::core::config::AppConfig;
use crate::protocols::ProtocolRegistry;
use crate::utils::error::{ConvertError, Result};
use tracing::info;

/// Handle validate command
pub async fn handle_validate(
    validate_cmd: &crate::commands::cli::Commands,
    _config: &AppConfig,
    _registry: &ProtocolRegistry,
) -> Result<()> {
    // 提取 Validate 命令的参数
    let (file, protocol, _format) = match validate_cmd {
        crate::commands::cli::Commands::Validate {
            file,
            protocol,
            format,
        } => (file, protocol, format),
        _ => {
            return Err(ConvertError::ConfigValidationError(
                "Expected Validate command".to_string(),
            ))
        }
    };

    // 验证协议
    let protocol_lower = protocol.to_lowercase();
    let protocol_name = match protocol_lower.as_str() {
        "singbox" | "sing-box" => "singbox",
        "clash" => "clash",
        "v2ray" => "v2ray",
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

    // 检查文件是否存在
    if !file.exists() {
        return Err(ConvertError::file_not_found(&file_path));
    }

    // 读取配置文件
    let content = std::fs::read_to_string(&*file_path).map_err(|e| ConvertError::IoError(e))?;

    // 根据协议验证配置
    match protocol_name {
        "singbox" => validate_singbox_config(&content)?,
        "clash" => validate_clash_config(&content)?,
        "v2ray" => validate_v2ray_config(&content)?,
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
