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
    let (output, template_type) = match template_cmd {
        crate::commands::cli::Commands::Template {
            output,
            template_type,
        } => (output, template_type),
        _ => {
            return Err(ConvertError::ConfigValidationError(
                "Expected Template command".to_string(),
            ))
        }
    };

    info!("Starting template generation");

    // 生成模板内容
    let template_content = match format!("{:?}", template_type).as_str() {
        "Basic" => generate_basic_template(),
        "Full" => generate_full_template(),
        "Minimal" => generate_minimal_template(),
        _ => {
            return Err(ConvertError::ConfigValidationError(format!(
                "不支持的模板类型: {:?}，支持的类型: Basic, Full, Minimal",
                template_type
            )))
        }
    };

    // 输出模板
    let output_path = output.to_str().unwrap();
    std::fs::write(output_path, template_content).map_err(|e| ConvertError::IoError(e))?;

    info!("模板已生成到: {}", output_path);
    info!("Template generation completed");
    Ok(())
}
