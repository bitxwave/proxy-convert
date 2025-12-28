//! Template command module

use crate::utils::error::{ConvertError, Result};
use crate::utils::template::template_engine::{
    generate_basic_template, generate_full_template, generate_minimal_template,
};
use tracing::info;

/// Handle template generation command
pub async fn handle_template(
    template_cmd: &crate::commands::cli::Commands,
    _config: &crate::core::config::AppConfig,
    _registry: &crate::protocols::ProtocolRegistry,
) -> Result<()> {
    // 提取 Template 命令的参数
    let (output, protocol, template_type) = match template_cmd {
        crate::commands::cli::Commands::Template {
            output,
            protocol,
            template_type,
        } => (output, protocol, template_type),
        _ => {
            return Err(ConvertError::ConfigValidationError(
                "Expected Template command".to_string(),
            ))
        }
    };

    // 验证协议
    let protocol_lower = protocol.to_lowercase();
    let (protocol_name, default_ext) = match protocol_lower.as_str() {
        "singbox" | "sing-box" => ("singbox", "json"),
        "clash" => ("clash", "yaml"),
        "v2ray" => ("v2ray", "json"),
        _ => {
            return Err(ConvertError::ConfigValidationError(format!(
                "Unsupported protocol: {}. Supported: singbox, clash, v2ray",
                protocol
            )))
        }
    };

    info!("Starting template generation for protocol: {}", protocol_name);

    // 生成模板内容
    let template_content = match format!("{:?}", template_type).as_str() {
        "Basic" => generate_basic_template(),
        "Full" => generate_full_template(),
        "Minimal" => generate_minimal_template(),
        _ => {
            return Err(ConvertError::ConfigValidationError(format!(
                "Unsupported template type: {:?}. Supported: Basic, Full, Minimal",
                template_type
            )))
        }
    };

    // 确定输出路径
    let output_path = if let Some(path) = output {
        path.to_string_lossy().to_string()
    } else {
        format!("template.{}", default_ext)
    };

    // 输出模板
    std::fs::write(&output_path, template_content).map_err(|e| ConvertError::IoError(e))?;

    info!("Template generated: {}", output_path);
    info!("Protocol: {}", protocol_name);
    Ok(())
}
