//! Convert command processing module

use crate::commands::cli;
use crate::protocols;
use crate::protocols::ProtocolRegistry;
use crate::utils::{
    error::{ConvertError, Result},
    source,
    template::template_engine,
};

/// source definition
#[derive(Debug, Clone)]
pub struct SourceMeta {
    pub name: Option<String>, // optional name
    pub source_type: SourceProtocol,
    pub source: String,
    pub format: Option<String>,
}

/// source type (subscription type)
#[derive(Debug, Clone)]
pub enum SourceProtocol {
    Clash,
    SingBox,
    V2Ray,
}

impl SourceProtocol {
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "clash" => Some(SourceProtocol::Clash),
            "sing-box" | "singbox" => Some(SourceProtocol::SingBox),
            "v2ray" => Some(SourceProtocol::V2Ray),
            _ => None,
        }
    }
}

/// Output protocol type
#[derive(Debug, Clone)]
pub enum OutputProtocol {
    SingBox,
    Clash,
    V2Ray,
}

impl OutputProtocol {
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "sing-box" | "singbox" => Some(OutputProtocol::SingBox),
            "clash" => Some(OutputProtocol::Clash),
            "v2ray" => Some(OutputProtocol::V2Ray),
            _ => None,
        }
    }

    /// Get the default output format for this protocol
    pub fn default_format(&self) -> cli::OutputFormat {
        match self {
            OutputProtocol::SingBox => cli::OutputFormat::Json,
            OutputProtocol::Clash => cli::OutputFormat::Yaml,
            OutputProtocol::V2Ray => cli::OutputFormat::Json,
        }
    }

    /// Get the default filename for this protocol
    pub fn default_filename(&self) -> &'static str {
        match self {
            OutputProtocol::SingBox => "config.json",
            OutputProtocol::Clash => "config.yaml",
            OutputProtocol::V2Ray => "config.json",
        }
    }
}

/// Convert command handler
pub struct ConvertCommand;

impl ConvertCommand {
    /// Execute conversion operation
    pub async fn start_convert(
        sources: &[String],
        _input_format: Option<&str>,
        output_protocol: &OutputProtocol,
        output: Option<&str>,
        template: Option<&str>,
        registry: &ProtocolRegistry,
        config: &crate::core::config::AppConfig,
    ) -> Result<()> {
        tracing::info!("Convert executing...");

        if sources.is_empty() {
            return Err(ConvertError::ConfigValidationError(
                "must specify at least one input source".to_string(),
            ));
        }

        // parse all sources
        let mut all_sources = Vec::new();
        for src in sources {
            all_sources.push(Self::parse_source_string(src)?);
        }

        // create template engine
        let mut template_engine = template_engine::TemplateEngine::new();

        // process each source
        for source_meta in &all_sources {
            let source = source::SourceLoader::load_source(source_meta, registry, config).await?;
            template_engine.add_source(source);
        }

        // process template
        let result = if let Some(template_path) = template {
            // Check if template file exists
            if !std::path::Path::new(template_path).exists() {
                return Err(ConvertError::file_not_found(template_path));
            }
            let template_content =
                std::fs::read_to_string(template_path).map_err(|e| ConvertError::IoError(e))?;
            template_engine.process_template(&template_content)?
        } else {
            Self::generate_default_config(&template_engine)?
        };

        // Get output format and filename based on protocol
        let output_format = output_protocol.default_format();
        let formatted_result = Self::format_output(&result, &output_format)?;
        // output result
        let output_path = Self::resolve_output_path(output, output_protocol)?;
        // Ensure parent directory exists
        if let Some(parent) = std::path::Path::new(&output_path).parent() {
            if !parent.exists() {
                std::fs::create_dir_all(parent).map_err(|e| ConvertError::IoError(e))?;
            }
        }
        std::fs::write(&output_path, formatted_result).map_err(|e| ConvertError::IoError(e))?;

        tracing::info!("config generated to: {}", output_path);

        Ok(())
    }

    /// Resolve output path, handling directory case
    fn resolve_output_path(
        output: Option<&str>,
        output_protocol: &OutputProtocol,
    ) -> Result<String> {
        use std::path::Path;

        let default_filename = output_protocol.default_filename();

        let output_path = output.unwrap_or(default_filename);
        let path = Path::new(output_path);

        // Check if path exists and is a directory
        if path.exists() && path.is_dir() {
            // If it's a directory, append default filename
            let file_path = path.join(default_filename);
            Ok(file_path.to_string_lossy().to_string())
        } else if path.exists() && path.is_file() {
            // If it's an existing file, use it directly
            Ok(output_path.to_string())
        } else {
            // If path doesn't exist, check if parent is a directory
            if let Some(parent) = path.parent() {
                if parent.exists() && !parent.is_dir() {
                    return Err(ConvertError::ConfigValidationError(format!(
                        "输出路径的父目录不是一个目录: {}",
                        parent.display()
                    )));
                }
            }
            // Path doesn't exist, assume it's a file path
            Ok(output_path.to_string())
        }
    }

    /// parse source string (name@type@source or type@source)
    /// type is required, supported types: clash, sing-box(singbox), v2ray
    fn parse_source_string(source_str: &str) -> Result<SourceMeta> {
        let parts: Vec<&str> = source_str.split('@').collect();

        match parts.as_slice() {
            [name, source_type, source] => {
                let source_type = SourceProtocol::from_str(source_type).ok_or_else(|| {
                    ConvertError::ConfigValidationError(format!(
                        "不支持的订阅类型: {}，支持的类型: clash, sing-box(singbox), v2ray",
                        source_type
                    ))
                })?;

                Ok(SourceMeta {
                    name: Some(name.to_string()),
                    source_type,
                    source: source.to_string(),
                    format: None,
                })
            }
            [source_type, source] => {
                // support type@source format (omit name)
                let source_type = SourceProtocol::from_str(source_type).ok_or_else(|| {
                    ConvertError::ConfigValidationError(format!(
                        "不支持的订阅类型: {}，支持的类型: clash, sing-box(singbox), v2ray",
                        source_type
                    ))
                })?;

                Ok(SourceMeta {
                    name: None, // omit name
                    source_type,
                    source: source.to_string(),
                    format: None,
                })
            }
            _ => Err(ConvertError::ConfigValidationError(format!(
                "订阅源格式错误，必须指定协议类型。格式: name@type@source 或 type@source，实际: {}",
                source_str
            ))),
        }
    }

    /// generate default config template (sing-box format)
    fn generate_default_config(
        template_engine: &template_engine::TemplateEngine,
    ) -> Result<String> {
        // Generate a basic sing-box config template without user-specific data
        let default_template = serde_json::json!({
            "log": {
                "level": "info",
                "timestamp": true
            },
            "dns": {
                "servers": [
                    {
                        "tag": "local",
                        "address": "223.5.5.5",
                        "detour": "DIRECT"
                    },
                    {
                        "tag": "remote",
                        "address": "8.8.8.8",
                        "detour": "Proxy"
                    }
                ],
                "final": "local",
                "strategy": "prefer_ipv4",
                "disable_cache": false,
                "disable_expire": false,
                "independent_cache": false,
                "reverse_mapping": false
            },
            "inbounds": [
                {
                    "type": "tun",
                    "tag": "TUN-IN",
                    "address": ["198.18.0.1/16", "fd00:1::1/64"],
                    "mtu": 9000,
                    "stack": "mixed",
                    "auto_route": true,
                    "strict_route": true,
                    "sniff": true,
                    "sniff_override_destination": true,
                    "endpoint_independent_nat": true
                }
            ],
            "outbounds": [
                {
                    "tag": "DIRECT",
                    "type": "direct"
                },
                {
                    "tag": "REJECT",
                    "type": "block"
                },
                {
                    "tag": "Proxy",
                    "type": "selector",
                    "interrupt_exist_connections": true,
                    "default": "Auto",
                    "outbounds": ["Auto", "Manual"]
                },
                {
                    "tag": "Auto",
                    "type": "urltest",
                    "url": "https://www.gstatic.com/generate_204",
                    "interval": "3m",
                    "tolerance": 50,
                    "idle_timeout": "5m",
                    "interrupt_exist_connections": true,
                    "outbounds": ["{{ALL-TAG}}"]
                },
                {
                    "tag": "Manual",
                    "type": "selector",
                    "interrupt_exist_connections": true,
                    "default": "",
                    "outbounds": ["{{ALL-TAG}}"]
                }
            ],
            "route": {
                "default_domain_resolver": {
                    "server": "local"
                },
                "rules": [
                    {"action": "sniff"},
                    {"action": "hijack-dns", "protocol": "dns"},
                    {"clash_mode": "global", "action": "route", "outbound": "Proxy"},
                    {"clash_mode": "direct", "action": "route", "outbound": "DIRECT"},
                    {"rule_set": "ads", "action": "reject", "method": "default", "no_drop": false},
                    {
                        "rule_set": ["microsoft-cn", "games-cn", "network-test", "applications", "cn", "cn-ip", "private-ip", "private"],
                        "action": "route",
                        "outbound": "DIRECT"
                    },
                    {
                        "action": "route",
                        "outbound": "TikTok",
                        "rule_set": ["google-cn", "apple-cn", "tiktok"],
                    },
                    {
                        "rule_set": ["proxy", "telegram-ip"],
                        "action": "route",
                        "outbound": "Proxy"
                    }
                ],
                "rule_set": [
                    {"tag": "ads", "type": "remote", "format": "binary", "url": "https://cdn.jsdelivr.net/gh/DustinWin/ruleset_geodata@sing-box-ruleset/ads.srs", "download_detour": "Proxy", "update_interval": "1d"},
                    {"tag": "private", "type": "remote", "format": "binary", "url": "https://cdn.jsdelivr.net/gh/DustinWin/ruleset_geodata@sing-box-ruleset/private.srs", "download_detour": "Proxy", "update_interval": "1d"},
                    {"tag": "microsoft-cn", "type": "remote", "format": "binary", "url": "https://cdn.jsdelivr.net/gh/DustinWin/ruleset_geodata@sing-box-ruleset/microsoft-cn.srs", "download_detour": "Proxy", "update_interval": "1d"},
                    {"tag": "apple-cn", "type": "remote", "format": "binary", "url": "https://cdn.jsdelivr.net/gh/DustinWin/ruleset_geodata@sing-box-ruleset/apple-cn.srs", "download_detour": "Proxy", "update_interval": "1d"},
                    {"tag": "google-cn", "type": "remote", "format": "binary", "url": "https://cdn.jsdelivr.net/gh/DustinWin/ruleset_geodata@sing-box-ruleset/google-cn.srs", "download_detour": "Proxy", "update_interval": "1d"},
                    {"tag": "games-cn", "type": "remote", "format": "binary", "url": "https://cdn.jsdelivr.net/gh/DustinWin/ruleset_geodata@sing-box-ruleset/games-cn.srs", "download_detour": "Proxy", "update_interval": "1d"},
                    {"tag": "network-test", "type": "remote", "format": "binary", "url": "https://cdn.jsdelivr.net/gh/DustinWin/ruleset_geodata@sing-box-ruleset/networktest.srs", "download_detour": "Proxy", "update_interval": "1d"},
                    {"tag": "applications", "type": "remote", "format": "binary", "url": "https://cdn.jsdelivr.net/gh/DustinWin/ruleset_geodata@sing-box-ruleset/applications.srs", "download_detour": "Proxy", "update_interval": "1d"},
                    {"tag": "proxy", "type": "remote", "format": "binary", "url": "https://cdn.jsdelivr.net/gh/DustinWin/ruleset_geodata@sing-box-ruleset/proxy.srs", "download_detour": "Proxy", "update_interval": "1d"},
                    {"tag": "cn", "type": "remote", "format": "binary", "url": "https://cdn.jsdelivr.net/gh/DustinWin/ruleset_geodata@sing-box-ruleset/cn.srs", "download_detour": "Proxy", "update_interval": "1d"},
                    {"tag": "telegram-ip", "type": "remote", "format": "binary", "url": "https://cdn.jsdelivr.net/gh/DustinWin/ruleset_geodata@sing-box-ruleset/telegramip.srs", "download_detour": "Proxy", "update_interval": "1d"},
                    {"tag": "private-ip", "type": "remote", "format": "binary", "url": "https://cdn.jsdelivr.net/gh/DustinWin/ruleset_geodata@sing-box-ruleset/privateip.srs", "download_detour": "Proxy", "update_interval": "1d"},
                    {"tag": "cn-ip", "type": "remote", "format": "binary", "url": "https://cdn.jsdelivr.net/gh/DustinWin/ruleset_geodata@sing-box-ruleset/cnip.srs", "download_detour": "Proxy", "update_interval": "1d"},
                    {"type": "remote", "tag": "tiktok", "format": "binary", "url": "https://cdn.jsdelivr.net/gh/DustinWin/ruleset_geodata@sing-box-ruleset/tiktok.srs", "download_detour": "Proxy", "update_interval": "1d"}
                ],
                "final": "Proxy",
                "auto_detect_interface": true
            },
            "experimental": {
                "cache_file": {
                    "enabled": true,
                    "path": "/etc/sing-box/cache.db",
                    "store_fakeip": false,
                    "store_rdrc": false
                },
                "clash_api": {
                    "external_controller": "0.0.0.0:9090",
                    "external_ui": "/etc/sing-box/dashboard",
                    "external_ui_download_url": "https://github.com/MetaCubeX/Yacd-meta/archive/gh-pages.zip",
                    "external_ui_download_detour": "Proxy",
                    "secret": "A9f#3kLp@7VzQx2M",
                    "default_mode": "rule"
                }
            }
        });

        // Convert to string and process template interpolation
        let template_str = serde_json::to_string(&default_template)
            .map_err(|e| ConvertError::JsonParseError(e))?;
        
        // Process template to replace interpolation rules like {{ALL-TAG}}
        template_engine.process_template(&template_str)
    }

    /// Format output based on the specified format
    fn format_output(content: &str, format: &cli::OutputFormat) -> Result<String> {
        match format {
            cli::OutputFormat::Json => {
                // Parse and re-serialize as pretty JSON (formatted)
                let parsed: serde_json::Value =
                    serde_json::from_str(content).map_err(|e| ConvertError::JsonParseError(e))?;
                Ok(serde_json::to_string_pretty(&parsed)
                    .map_err(|e| ConvertError::JsonParseError(e))?)
            }
            cli::OutputFormat::Yaml => {
                // Parse JSON and convert to YAML
                let parsed: serde_json::Value =
                    serde_json::from_str(content).map_err(|e| ConvertError::JsonParseError(e))?;
                Ok(serde_yaml::to_string(&parsed)
                    .map_err(|e| ConvertError::ConfigValidationError(e.to_string()))?)
            }
        }
    }
}

/// Handle convert command
pub async fn handle_convert(
    convert_cmd: &cli::Commands,
    config: &crate::core::config::AppConfig,
    registry: &protocols::ProtocolRegistry,
) -> Result<()> {
    // 提取 Convert 命令的参数
    let (sources, output, template, output_protocol_str) = match convert_cmd {
        cli::Commands::Convert {
            sources,
            output,
            template,
            output_protocol,
            ..
        } => (sources, output, template, output_protocol),
        _ => {
            return Err(ConvertError::ConfigValidationError(
                "Expected Convert command".to_string(),
            ))
        }
    };

    // 合并 sources：命令行的在前，配置文件的在后
    let mut final_sources: Vec<String> = sources.clone();
    if let Some(config_sources) = &config.sources {
        for s in config_sources {
            final_sources.push(format!("{}@{}@{}", s.name, s.source_type, s.url));
        }
    }

    // 确定输出协议：优先使用 CLI 参数，其次使用配置文件（默认值为 sing-box）
    let output_protocol_str = output_protocol_str
        .as_ref()
        .map(|s| s.as_str())
        .unwrap_or_else(|| config.output_protocol.as_str());

    let output_protocol = OutputProtocol::from_str(output_protocol_str).ok_or_else(|| {
        ConvertError::ConfigValidationError(format!(
            "不支持的输出协议: {}，支持的协议: sing-box(singbox), clash, v2ray。当前仅支持 sing-box",
            output_protocol_str
        ))
    })?;

    // 验证当前仅支持 sing-box
    match output_protocol {
        OutputProtocol::SingBox => {
            // 允许
        }
        OutputProtocol::Clash | OutputProtocol::V2Ray => {
            return Err(ConvertError::ConfigValidationError(format!(
                "输出协议 {} 暂不支持，当前仅支持 sing-box",
                output_protocol_str
            )));
        }
    }

    // 合并 output：CLI > 配置文件 > 默认值
    let final_output: Option<String> = output
        .as_ref()
        .and_then(|p| p.to_str())
        .map(|s| s.to_string())
        .or_else(|| config.output.clone());

    // 合并 template：CLI > 配置文件 > None（使用内存默认模板）
    let final_template: Option<String> = template
        .as_ref()
        .and_then(|p| p.to_str())
        .map(|s| s.to_string())
        .or_else(|| config.template.clone());

    tracing::info!("Starting conversion");
    tracing::info!("Input sources: {:?}", final_sources);
    tracing::info!(
        "Template: {}",
        final_template.as_deref().unwrap_or("(default)")
    );
    tracing::info!(
        "Output: {}",
        final_output.as_deref().unwrap_or("(default)")
    );
    tracing::info!("Output protocol: {}", output_protocol_str);
    tracing::info!(
        "Output format: {}",
        match output_protocol.default_format() {
            cli::OutputFormat::Json => "JSON",
            cli::OutputFormat::Yaml => "YAML",
        }
    );
    tracing::info!("Using timeout: {} seconds", config.timeout_seconds);

    // 调用转换命令
    ConvertCommand::start_convert(
        final_sources.as_slice(),
        None, // input_format
        &output_protocol,
        final_output.as_deref(),
        final_template.as_deref(),
        registry,
        config,
    )
    .await?;

    tracing::info!("Conversion completed");
    Ok(())
}
