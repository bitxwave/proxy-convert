//! Config management - load and merge application configuration.

use crate::core::error::{ConvertError, Result};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppConfig {
    // ========== HTTP ==========
    /// HTTP User-Agent
    #[serde(default = "default_user_agent")]
    pub user_agent: String,

    /// HTTP timeout in seconds
    #[serde(default = "default_timeout")]
    pub timeout_seconds: u64,

    /// Retry count on failure
    #[serde(default = "default_retry_count")]
    pub retry_count: u32,

    // ========== Logging ==========
    /// Log level: error, warn, info, debug, trace
    #[serde(default = "default_log_level")]
    pub log_level: String,

    /// Verbose output
    #[serde(default)]
    pub verbose: bool,

    // ========== Output ==========
    /// Output protocol: singbox, clash, v2ray
    #[serde(default = "default_output_protocol")]
    pub output_protocol: String,

    /// Output file path
    #[serde(default)]
    pub output: Option<String>,

    // ========== Template ==========
    /// Template file path
    #[serde(default)]
    pub template: Option<String>,

    // ========== Sources ==========
    /// Source list; each item is URL form: <path|url>?type=clash&name=...&flag=... (same as --source)
    #[serde(default)]
    pub sources: Option<Vec<String>>,
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
    /// Load config: optional file from default paths (first existing) + env vars.
    /// Env vars (PROXY_CONVERT_*) override file. Used when no explicit config path is given.
    fn load_default_locations() -> Result<Self> {
        let paths = Self::get_config_paths();
        let mut builder = config::Config::builder();

        for path in &paths {
            if path.exists() {
                builder = builder.add_source(config::File::from(path.as_path()).required(true));
                tracing::info!("Load config file: {}", path.display());
                break;
            }
        }
        builder = builder.add_source(
            config::Environment::with_prefix("PROXY_CONVERT").separator("__"),
        );
        let c = builder
            .build()
            .map_err(|e| ConvertError::ConfigValidationError(e.to_string()))?;
        let config: AppConfig = c
            .try_deserialize()
            .map_err(|e| ConvertError::ConfigValidationError(e.to_string()))?;
        if !paths.iter().any(|p| p.exists()) {
            tracing::info!("No config file found, using defaults and env");
        }
        Ok(config)
    }

    pub fn load() -> Result<Self> {
        Self::load_default_locations()
    }

    fn get_config_paths() -> Vec<PathBuf> {
        let mut paths = Vec::new();

        // Current directory
        paths.push(PathBuf::from("config.yaml"));
        paths.push(PathBuf::from("config.yml"));

        // User config directory
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
            // Merge timeout
            if let Some(timeout_val) = timeout {
                self.timeout_seconds = *timeout_val;
                tracing::debug!(
                    "CLI timeout parameter overrides config: {} seconds",
                    timeout_val
                );
            }

            // Merge output protocol
            if let Some(protocol) = output_protocol {
                self.output_protocol = protocol.clone();
                tracing::debug!(
                    "CLI output protocol parameter overrides config: {}",
                    protocol
                );
            }

            // Merge verbose
            if *verbose {
                self.verbose = true;
                tracing::debug!("CLI verbose parameter overrides config: true");
            }

            // Merge log level
            let cli_log_level = format!("{:?}", log_level).to_lowercase();
            if cli_log_level != "info" {
                // Override only when CLI specifies non-default
                self.log_level = cli_log_level.clone();
                tracing::debug!(
                    "CLI log_level parameter overrides config: {}",
                    cli_log_level
                );
            }

            // Merge template
            if let Some(tpl) = template {
                self.template = Some(tpl.to_string_lossy().to_string());
                tracing::debug!("CLI template parameter overrides config: {:?}", tpl);
            }

            // Merge output path (only when CLI specifies)
            if let Some(out) = output {
                let output_str = out.to_string_lossy().to_string();
                self.output = Some(output_str.clone());
                tracing::debug!("CLI output parameter overrides config: {}", output_str);
            }
        }
        Ok(())
    }

    /// Load application configuration.
    /// Priority: explicit path (if given) > default paths (first existing) > env (PROXY_CONVERT_*) > serde defaults.
    pub fn load_from_path(config_path: Option<&str>) -> Result<Self> {
        let config = if let Some(path) = config_path {
            let c = config::Config::builder()
                .add_source(config::File::from(std::path::Path::new(path)).required(true))
                .add_source(
                    config::Environment::with_prefix("PROXY_CONVERT").separator("__"),
                )
                .build()
                .map_err(|e| ConvertError::ConfigValidationError(e.to_string()))?;

            c.try_deserialize().map_err(|e| {
                ConvertError::ConfigValidationError(e.to_string())
            })?
        } else {
            Self::load_default_locations()?
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
    fn test_source_string_format() {
        let source = "https://example.com/config.yaml?type=clash&name=test-source";
        assert!(source.contains('?'));
        assert!(source.contains("type=clash"));
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
            "https://example.com/clash.yaml?type=clash&name=source1".to_string(),
            "https://example.com/singbox.json?type=singbox&name=source2".to_string(),
        ]);

        assert!(config.sources.is_some());
        let sources = config.sources.as_ref().unwrap();
        assert_eq!(sources.len(), 2);
        assert!(sources[0].contains("name=source1"));
        assert!(sources[1].contains("name=source2"));
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
            sources: Some(vec!["https://custom.com/config.json?type=v2ray&name=custom-source".to_string()]),
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
    fn test_sources_list_clone() {
        let sources = Some(vec!["https://example.com?type=clash".to_string()]);
        let c = sources.clone();
        assert_eq!(sources.as_ref().unwrap()[0], c.as_ref().unwrap()[0]);
    }
}
