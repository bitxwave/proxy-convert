//! Convert command processing module

use crate::commands::cli;
use crate::protocols;
use crate::protocols::ProtocolRegistry;
use crate::protocols::singbox;
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
    /// If set, use this flag when requesting URL (empty string = &flag=); else use protocol default
    pub flag: Option<String>,
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
        sources: &[SourceMeta],
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

        // create template engine
        let mut template_engine = template_engine::TemplateEngine::new();

        // process each source
        for source_meta in sources.iter() {
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
            Self::generate_default_config(&template_engine, output_protocol)?
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
                        "Output path parent is not a directory: {}",
                        parent.display()
                    )));
                }
            }
            // Path doesn't exist, assume it's a file path
            Ok(output_path.to_string())
        }
    }

    /// Parse source string: only URL form <path|url>?type=...&name=...&flag=... (type required in query).
    pub fn parse_source_string(raw: &str) -> Result<SourceMeta> {
        let raw = raw.trim();
        let pos = raw.find('?').ok_or_else(|| {
            ConvertError::ConfigValidationError(format!(
                "Source must be URL form with query params. Example: <path|url>?type=clash&name=...&flag=..., got: {}",
                raw
            ))
        })?;
        let (_base, query_str) = raw.split_at(pos);
        let query_str = query_str.trim_start_matches('?');
        let mut name: Option<String> = None;
        let mut type_param: Option<String> = None;
        let mut flag: Option<String> = None;
        for (k, v) in url::form_urlencoded::parse(query_str.as_bytes()) {
            match k.as_ref() {
                "name" => name = Some(v.into_owned()),
                "type" => type_param = Some(v.into_owned()),
                "flag" => flag = Some(v.into_owned()),
                _ => {}
            }
        }
        let source_type_str = type_param.ok_or_else(|| {
            ConvertError::ConfigValidationError(
                "Query must include type param. Example: url?type=clash&name=my&flag=clash".to_string(),
            )
        })?;
        let source_type = SourceProtocol::from_str(&source_type_str).ok_or_else(|| {
            ConvertError::ConfigValidationError(format!(
                "Unsupported type: {}, supported: clash, sing-box(singbox), v2ray",
                source_type_str
            ))
        })?;
        // Keep full string (path|url + all query params); type/name/flag are parsed out but remain in source
        Ok(SourceMeta {
            name: name.filter(|s| !s.is_empty()),
            source_type,
            source: raw.to_string(),
            format: None,
            flag,
        })
    }

    /// generate default config template based on output protocol
    fn generate_default_config(
        template_engine: &template_engine::TemplateEngine,
        output_protocol: &OutputProtocol,
    ) -> Result<String> {
        // Get default template from the protocol module based on output protocol
        let template_str = match output_protocol {
            OutputProtocol::SingBox => singbox::generate_default_template(),
            OutputProtocol::Clash => protocols::clash::generate_default_template(),
            OutputProtocol::V2Ray => protocols::v2ray::generate_default_template(),
        };

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
    // Extract Convert command args
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

    // Parse each source (CLI + config): <path|url>?type=...&name=...&flag=...
    let mut final_sources: Vec<SourceMeta> = sources
        .iter()
        .map(|raw| ConvertCommand::parse_source_string(raw))
        .collect::<Result<Vec<_>>>()?;
    if let Some(config_sources) = &config.sources {
        for raw in config_sources {
            final_sources.push(ConvertCommand::parse_source_string(raw)?);
        }
    }

    // Output protocol: CLI > config > default (sing-box)
    let output_protocol_str = output_protocol_str
        .as_ref()
        .map(|s| s.as_str())
        .unwrap_or_else(|| config.output_protocol.as_str());

    let output_protocol = OutputProtocol::from_str(output_protocol_str).ok_or_else(|| {
        ConvertError::ConfigValidationError(format!(
            "Unsupported output protocol: {}, supported protocols: sing-box(singbox), clash, v2ray",
            output_protocol_str
        ))
    })?;

    // Merge output: CLI > config > default
    let final_output: Option<String> = output
        .as_ref()
        .and_then(|p| p.to_str())
        .map(|s| s.to_string())
        .or_else(|| config.output.clone());

    // Merge template: CLI > config > None (in-memory default)
    let final_template: Option<String> = template
        .as_ref()
        .and_then(|p| p.to_str())
        .map(|s| s.to_string())
        .or_else(|| config.template.clone());

    tracing::info!("Starting conversion");
    for (i, m) in final_sources.iter().enumerate() {
        let type_str = match &m.source_type {
            SourceProtocol::Clash => "clash",
            SourceProtocol::SingBox => "singbox",
            SourceProtocol::V2Ray => "v2ray",
        };
        let name_str = m.name.as_deref().unwrap_or("(none)");
        let flag_str = m.flag.as_deref().unwrap_or("(default)");
        tracing::info!(
            "Input source [{}]: {}  type={} name={} flag={}",
            i + 1,
            m.source,
            type_str,
            name_str,
            flag_str
        );
    }
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

    // Run conversion
    ConvertCommand::start_convert(
        &final_sources,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_source_string_url_format() {
        // Path + type only; source keeps full string (all params)
        let m = ConvertCommand::parse_source_string("./config.yaml?type=clash").unwrap();
        assert_eq!(m.name, None);
        assert!(matches!(m.source_type, SourceProtocol::Clash));
        assert_eq!(m.source, "./config.yaml?type=clash");
        assert_eq!(m.flag, None);

        // URL + type, name, flag
        let m = ConvertCommand::parse_source_string(
            "https://example.com/sub?type=singbox&name=my&flag=sing-box",
        )
        .unwrap();
        assert_eq!(m.name.as_deref(), Some("my"));
        assert!(matches!(m.source_type, SourceProtocol::SingBox));
        assert_eq!(
            m.source,
            "https://example.com/sub?type=singbox&name=my&flag=sing-box"
        );
        assert_eq!(m.flag.as_deref(), Some("sing-box"));

        // File path with space (Eternal Network style); source keeps full string
        let m = ConvertCommand::parse_source_string("examples/sources/Eternal Network?type=singbox")
            .unwrap();
        assert_eq!(m.name, None);
        assert!(matches!(m.source_type, SourceProtocol::SingBox));
        assert_eq!(m.source, "examples/sources/Eternal Network?type=singbox");

        // Empty name filtered out; source keeps full string including other params
        let m = ConvertCommand::parse_source_string("./x?type=clash&name=").unwrap();
        assert_eq!(m.name, None);
        assert_eq!(m.source, "./x?type=clash&name=");
    }

    #[test]
    fn test_parse_source_string_requires_type() {
        let err = ConvertCommand::parse_source_string("./x?name=foo")
            .unwrap_err();
        let msg = format!("{}", err);
        assert!(msg.contains("type") || msg.contains("Query must include"));
    }

    #[test]
    fn test_parse_source_string_rejects_no_query() {
        let err = ConvertCommand::parse_source_string("clash@./clash.yaml").unwrap_err();
        let msg = format!("{}", err);
        assert!(msg.contains("query") || msg.contains("URL form"));
    }

    #[test]
    fn test_parse_source_string_unsupported_type() {
        let err = ConvertCommand::parse_source_string("./x?type=unknown").unwrap_err();
        let msg = format!("{}", err);
        assert!(msg.contains("Unsupported") || msg.contains("unknown"));
    }
}
