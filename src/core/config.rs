//! 配置管理模块 - 处理应用程序配置的加载和管理

use crate::utils::error::{ConvertError, Result};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppConfig {
    // ========== HTTP 请求配置 ==========
    /// HTTP 请求 User-Agent
    #[serde(default = "default_user_agent")]
    pub user_agent: String,

    /// HTTP 请求超时（秒）
    #[serde(default = "default_timeout")]
    pub timeout_seconds: u64,

    /// 失败重试次数
    #[serde(default = "default_retry_count")]
    pub retry_count: u32,

    // ========== 日志配置 ==========
    /// 日志级别: error, warn, info, debug, trace
    #[serde(default = "default_log_level")]
    pub log_level: String,

    /// 是否显示详细信息
    #[serde(default)]
    pub verbose: bool,

    // ========== 输出配置 ==========
    /// 输出协议: singbox, clash, v2ray（目前仅支持 singbox）
    #[serde(default = "default_output_protocol")]
    pub output_protocol: String,

    /// 输出文件路径
    #[serde(default)]
    pub output: Option<String>,

    // ========== 模板配置 ==========
    /// 模板文件路径
    #[serde(default)]
    pub template: Option<String>,

    // ========== 订阅源配置 ==========
    /// 订阅源列表
    #[serde(default)]
    pub sources: Option<Vec<SourceConfig>>,
}

/// 订阅源配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceConfig {
    /// 源名称（用于标识和区分多个源）
    pub name: String,
    /// 源类型: clash, singbox, v2ray（必填）
    #[serde(rename = "type")]
    pub source_type: String,
    /// 源路径或 URL
    pub url: String,
}

fn default_user_agent() -> String {
    "Mozilla/5.0 (compatible; ProxyConvert/2.0)".to_string()
}

fn default_timeout() -> u64 {
    30
}

fn default_retry_count() -> u32 {
    3
}

fn default_log_level() -> String {
    "info".to_string()
}

fn default_output_protocol() -> String {
    "singbox".to_string()
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            user_agent: default_user_agent(),
            timeout_seconds: default_timeout(),
            retry_count: default_retry_count(),
            log_level: default_log_level(),
            verbose: false,
            output_protocol: default_output_protocol(),
            output: None,
            template: None,
            sources: None,
        }
    }
}

impl AppConfig {
    pub fn load() -> Result<Self> {
        let config_paths = Self::get_config_paths();

        for path in config_paths {
            if path.exists() {
                let config_str =
                    std::fs::read_to_string(&path).map_err(|e| ConvertError::IoError(e))?;

                let config: AppConfig = serde_yaml::from_str(&config_str)
                    .map_err(|e| ConvertError::ConfigValidationError(e.to_string()))?;

                tracing::info!("Load config file: {}", path.display());
                return Ok(config);
            }
        }

        tracing::info!("Using default config");
        Ok(Self::default())
    }

    fn get_config_paths() -> Vec<PathBuf> {
        let mut paths = Vec::new();

        // 当前目录
        paths.push(PathBuf::from("config.yaml"));
        paths.push(PathBuf::from("config.yml"));

        // 用户配置目录
        if let Some(config_dir) = dirs::config_dir() {
            let app_config_dir = config_dir.join("proxy-convert");
            paths.push(app_config_dir.join("config.yaml"));
            paths.push(app_config_dir.join("config.yml"));
        }

        paths
    }

    /// Merge CLI parameters into config (CLI parameters take precedence)
    pub fn merge_cli_params(&mut self, cli: &crate::commands::cli::Commands) -> Result<()> {
        if let crate::commands::cli::Commands::Convert {
            timeout,
            output_protocol,
            verbose,
            log_level,
            template,
            output,
            ..
        } = cli
        {
            // 合并超时参数
            if let Some(timeout_val) = timeout {
                self.timeout_seconds = *timeout_val;
                tracing::debug!(
                    "CLI timeout parameter overrides config: {} seconds",
                    timeout_val
                );
            }

            // 合并输出协议参数
            if let Some(protocol) = output_protocol {
                self.output_protocol = protocol.clone();
                tracing::debug!(
                    "CLI output protocol parameter overrides config: {}",
                    protocol
                );
            }

            // 合并详细信息参数
            if *verbose {
                self.verbose = true;
                tracing::debug!("CLI verbose parameter overrides config: true");
            }

            // 合并日志级别参数
            let cli_log_level = format!("{:?}", log_level).to_lowercase();
            if cli_log_level != "info" {
                // 只有当 CLI 指定了非默认值时才覆盖
                self.log_level = cli_log_level.clone();
                tracing::debug!(
                    "CLI log_level parameter overrides config: {}",
                    cli_log_level
                );
            }

            // 合并模板参数
            if let Some(tpl) = template {
                self.template = Some(tpl.to_string_lossy().to_string());
                tracing::debug!("CLI template parameter overrides config: {:?}", tpl);
            }

            // 合并输出路径参数（仅当 CLI 指定时）
            if let Some(out) = output {
                let output_str = out.to_string_lossy().to_string();
                self.output = Some(output_str.clone());
                tracing::debug!("CLI output parameter overrides config: {}", output_str);
            }
        }
        Ok(())
    }

    /// Load application configuration
    pub fn load_from_path(config_path: Option<&str>) -> Result<Self> {
        let config = if let Some(path) = config_path {
            // Load configuration from specified path
            let config = config::Config::builder()
                .add_source(config::File::from(std::path::Path::new(path)))
                .add_source(config::Environment::with_prefix("PROXY_CONVERT"))
                .build()
                .map_err(|e| {
                    crate::utils::error::ConvertError::ConfigValidationError(e.to_string())
                })?;

            config.try_deserialize().map_err(|e| {
                crate::utils::error::ConvertError::ConfigValidationError(e.to_string())
            })?
        } else {
            // Use default configuration
            Self::load().map_err(|e| {
                crate::utils::error::ConvertError::ConfigValidationError(e.to_string())
            })?
        };

        tracing::info!("Configuration loaded successfully");
        Ok(config)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = AppConfig::default();

        assert_eq!(
            config.user_agent,
            "Mozilla/5.0 (compatible; ProxyConvert/2.0)"
        );
        assert_eq!(config.timeout_seconds, 30);
        assert_eq!(config.retry_count, 3);
        assert_eq!(config.log_level, "info");
        assert!(!config.verbose);
        assert_eq!(config.output_protocol, "singbox");
        assert!(config.output.is_none());
        assert!(config.template.is_none());
        assert!(config.sources.is_none());
    }

    #[test]
    fn test_source_config_creation() {
        let source = SourceConfig {
            name: "test-source".to_string(),
            source_type: "clash".to_string(),
            url: "https://example.com/config.yaml".to_string(),
        };

        assert_eq!(source.name, "test-source");
        assert_eq!(source.source_type, "clash");
        assert_eq!(source.url, "https://example.com/config.yaml");
    }

    #[test]
    fn test_config_serialization() {
        let config = AppConfig::default();
        let json = serde_json::to_string(&config).unwrap();
        let deserialized: AppConfig = serde_json::from_str(&json).unwrap();

        assert_eq!(config.user_agent, deserialized.user_agent);
        assert_eq!(config.timeout_seconds, deserialized.timeout_seconds);
        assert_eq!(config.retry_count, deserialized.retry_count);
    }

    #[test]
    fn test_config_with_sources() {
        let mut config = AppConfig::default();
        config.sources = Some(vec![
            SourceConfig {
                name: "source1".to_string(),
                source_type: "clash".to_string(),
                url: "https://example.com/clash.yaml".to_string(),
            },
            SourceConfig {
                name: "source2".to_string(),
                source_type: "singbox".to_string(),
                url: "https://example.com/singbox.json".to_string(),
            },
        ]);

        assert!(config.sources.is_some());
        let sources = config.sources.unwrap();
        assert_eq!(sources.len(), 2);
        assert_eq!(sources[0].name, "source1");
        assert_eq!(sources[1].name, "source2");
    }

    #[test]
    fn test_config_yaml_serialization() {
        let config = AppConfig::default();
        let yaml = serde_yaml::to_string(&config).unwrap();
        let deserialized: AppConfig = serde_yaml::from_str(&yaml).unwrap();

        assert_eq!(config.user_agent, deserialized.user_agent);
        assert_eq!(config.timeout_seconds, deserialized.timeout_seconds);
        assert_eq!(config.retry_count, deserialized.retry_count);
    }

    #[test]
    fn test_config_with_custom_values() {
        let config = AppConfig {
            user_agent: "Custom Agent".to_string(),
            timeout_seconds: 60,
            retry_count: 5,
            log_level: "debug".to_string(),
            verbose: true,
            output_protocol: "singbox".to_string(),
            output: Some("output.json".to_string()),
            template: Some("./template.json".to_string()),
            sources: Some(vec![SourceConfig {
                name: "custom-source".to_string(),
                source_type: "v2ray".to_string(),
                url: "https://custom.com/config.json".to_string(),
            }]),
        };

        assert_eq!(config.user_agent, "Custom Agent");
        assert_eq!(config.timeout_seconds, 60);
        assert_eq!(config.retry_count, 5);
        assert_eq!(config.log_level, "debug");
        assert!(config.verbose);
        assert_eq!(config.output_protocol, "singbox");
        assert_eq!(config.output, Some("output.json".to_string()));
        assert_eq!(config.template, Some("./template.json".to_string()));
        assert!(config.sources.is_some());
    }

    #[test]
    fn test_config_clone() {
        let config1 = AppConfig::default();
        let config2 = config1.clone();

        assert_eq!(config1.user_agent, config2.user_agent);
        assert_eq!(config1.timeout_seconds, config2.timeout_seconds);
        assert_eq!(config1.retry_count, config2.retry_count);
    }

    #[test]
    fn test_source_config_clone() {
        let source1 = SourceConfig {
            name: "test".to_string(),
            source_type: "clash".to_string(),
            url: "https://example.com".to_string(),
        };
        let source2 = source1.clone();

        assert_eq!(source1.name, source2.name);
        assert_eq!(source1.source_type, source2.source_type);
        assert_eq!(source1.url, source2.url);
    }
}
