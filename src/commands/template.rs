//! Template command module

use crate::protocols::{clash, singbox, v2ray};
use crate::utils::error::{ConvertError, Result};
use tracing::info;

/// Handle template generation command
pub async fn handle_template(
    template_cmd: &crate::commands::cli::Commands,
    _config: &crate::core::config::AppConfig,
    _registry: &crate::protocols::ProtocolRegistry,
) -> Result<()> {
    // 提取 Template 命令的参数
    let (output, protocol) = match template_cmd {
        crate::commands::cli::Commands::Template { output, protocol } => (output, protocol),
        _ => {
            return Err(ConvertError::ConfigValidationError(
                "Expected Template command".to_string(),
            ))
        }
    };

    // 验证协议并生成对应模板
    let protocol_lower = protocol.to_lowercase();
    let (protocol_name, default_ext, template_content) = match protocol_lower.as_str() {
        "singbox" | "sing-box" => (
            singbox::PROTOCOL_NAME,
            singbox::CONFIG_EXT,
            singbox::generate_default_template(),
        ),
        "clash" => (
            clash::PROTOCOL_NAME,
            clash::CONFIG_EXT,
            clash::generate_default_template(),
        ),
        "v2ray" => (
            v2ray::PROTOCOL_NAME,
            v2ray::CONFIG_EXT,
            v2ray::generate_default_template(),
        ),
        _ => {
            return Err(ConvertError::ConfigValidationError(format!(
                "Unsupported protocol: {}. Supported: singbox, clash, v2ray",
                protocol
            )))
        }
    };

    info!(
        "Starting template generation for protocol: {}",
        protocol_name
    );

    // 确定输出路径
    let output_path = if let Some(path) = output {
        path.to_string_lossy().to_string()
    } else {
        format!("template.{}", default_ext)
    };

    // 输出模板
    std::fs::write(&output_path, &template_content).map_err(|e| ConvertError::IoError(e))?;

    info!("Template generated: {}", output_path);
    info!("Protocol: {}", protocol_name);
    Ok(())
}
