//! Source loader for loading and parsing configurations

use crate::commands::convert::{SourceMeta, SourceProtocol};
use crate::core::config::AppConfig;
use crate::protocols::{clash, singbox, v2ray, ProtocolRegistry};
use crate::utils::error::{ConvertError, Result};
use crate::utils::source::parser::{Config, Source};
use std::io::{Error, ErrorKind};
use std::path::Path;

/// Source loader for loading and parsing configurations
pub struct SourceLoader;

impl SourceLoader {
    /// Load and parse a source configuration
    pub async fn load_source(
        source_meta: &SourceMeta,
        registry: &ProtocolRegistry,
        config: &AppConfig,
    ) -> Result<Source> {
        let content =
            Self::load_content_from_source(&source_meta.source, &source_meta.source_type, config)
                .await?;

        // Determine the format
        let detected_format = if let Some(fmt) = &source_meta.format {
            fmt.clone()
        } else {
            match &source_meta.source_type {
                SourceProtocol::Clash => "clash".to_string(),
                SourceProtocol::SingBox => "singbox".to_string(),
                SourceProtocol::V2Ray => "v2ray".to_string(),
            }
        };

        // Parse configuration based on detected format
        let parsed_config = Self::parse_config(&content, &detected_format, registry)?;

        Ok(Source::new(source_meta.clone(), parsed_config))
    }

    /// Load content from source (URL or local file)
    async fn load_content_from_source(
        source: &str,
        source_type: &SourceProtocol,
        config: &AppConfig,
    ) -> Result<String> {
        if source.starts_with("http://") || source.starts_with("https://") {
            // Load from URL with appropriate flag parameter
            let url_with_flag = Self::append_flag_to_url(source, source_type);
            Self::load_from_url(&url_with_flag, config).await
        } else {
            // Load from local file
            Self::load_from_file(source)
        }
    }

    /// Append or update flag query parameter to URL based on source type
    /// - sing-box format: adds/updates &flag=sing-box
    /// - clash format: adds/updates &flag=clash
    /// - v2ray format: adds/updates &flag=v2ray
    /// If flag parameter already exists with a different value, it will be updated.
    fn append_flag_to_url(url: &str, source_type: &SourceProtocol) -> String {
        let flag_value = match source_type {
            SourceProtocol::Clash => "clash",
            SourceProtocol::SingBox => "sing-box",
            SourceProtocol::V2Ray => "v2ray",
        };

        // Check if flag parameter already exists and get its value
        if let Some(current_flag_value) = Self::get_flag_param_value(url) {
            // Flag parameter exists, check if value matches
            if current_flag_value == flag_value {
                // Value matches, return URL as-is
                url.to_string()
            } else {
                // Value doesn't match, update it
                Self::update_flag_param(url, flag_value)
            }
        } else {
            // Flag parameter doesn't exist, add it
            if url.contains('?') {
                format!("{}&flag={}", url, flag_value)
            } else {
                format!("{}?flag={}", url, flag_value)
            }
        }
    }

    /// Get the value of the flag parameter from URL, if it exists
    fn get_flag_param_value(url: &str) -> Option<String> {
        // Find the query string part (after ?)
        if let Some(query_start) = url.find('?') {
            let query_part = &url[query_start + 1..];
            // Also check for fragment separator
            let query_end = query_part.find('#').unwrap_or(query_part.len());
            let query = &query_part[..query_end];
            
            // Find flag parameter in query string
            for param in query.split('&') {
                let param = param.trim_start_matches('?');
                if let Some(flag_start) = param.find("flag=") {
                    let value = &param[flag_start + 5..];
                    // Get value up to next & or end of string
                    let value_end = value.find('&').unwrap_or(value.len());
                    return Some(value[..value_end].to_string());
                }
            }
        }
        None
    }

    /// Update the flag parameter value in URL
    fn update_flag_param(url: &str, new_flag_value: &str) -> String {
        // Find the query string part
        if let Some(query_start) = url.find('?') {
            let base_url = &url[..query_start + 1];
            let query_part = &url[query_start + 1..];
            
            // Check for fragment
            let (query, fragment) = if let Some(frag_start) = query_part.find('#') {
                (&query_part[..frag_start], Some(&query_part[frag_start..]))
            } else {
                (query_part, None)
            };
            
            // Split query parameters and update flag
            let params: Vec<String> = query
                .split('&')
                .map(|p| {
                    if p.trim_start_matches('?').starts_with("flag=") {
                        format!("flag={}", new_flag_value)
                    } else {
                        p.to_string()
                    }
                })
                .collect();
            
            // Reconstruct URL
            let mut result = base_url.to_string();
            if !params.is_empty() {
                result.push_str(&params.join("&"));
            }
            if let Some(frag) = fragment {
                result.push_str(frag);
            }
            result
        } else {
            // No query string, just add flag parameter
            format!("{}?flag={}", url, new_flag_value)
        }
    }

    /// Load content from URL
    async fn load_from_url(url: &str, config: &AppConfig) -> Result<String> {
        tracing::info!("Fetching URL: {}", url);

        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(config.timeout_seconds))
            .build()
            .map_err(|e| ConvertError::IoError(Error::new(ErrorKind::Other, e)))?;

        let response = client
            .get(url)
            .send()
            .await
            .map_err(|e| ConvertError::IoError(Error::new(ErrorKind::Other, e)))?;

        if !response.status().is_success() {
            return Err(ConvertError::ConfigValidationError(format!(
                "Failed to fetch URL: {} - Status: {}",
                url,
                response.status()
            )));
        }

        let content = response
            .text()
            .await
            .map_err(|e| ConvertError::IoError(Error::new(ErrorKind::Other, e)))?;

        Ok(content)
    }

    /// Load content from local file
    fn load_from_file(file_path: &str) -> Result<String> {
        let path = Path::new(file_path);
        if !path.exists() {
            return Err(ConvertError::file_not_found(file_path));
        }

        std::fs::read_to_string(path).map_err(|e| ConvertError::IoError(e))
    }

    /// Parse configuration based on format (strongly typed)
    fn parse_config(content: &str, format: &str, registry: &ProtocolRegistry) -> Result<Config> {
        match format.to_lowercase().as_str() {
            "clash" => {
                let config = Self::parse_clash_config(content)?;
                Ok(Config::Clash(config))
            }
            "singbox" => {
                let config = Self::parse_singbox_config(content)?;
                Ok(Config::SingBox(config))
            }
            "v2ray" => {
                let config = Self::parse_v2ray_config(content)?;
                Ok(Config::V2Ray(config))
            }
            "subscription" => {
                let servers = registry.parse_subscription_format_pub(content)?;
                Ok(Config::Subscription(servers))
            }
            "plain" => {
                let servers = registry.parse_plain_text_format_pub(content)?;
                Ok(Config::Plain(servers))
            }
            _ => Err(ConvertError::ConfigValidationError(format!(
                "Unsupported format: {}",
                format
            ))),
        }
    }

    /// Parse Clash configuration (strongly typed)
    fn parse_clash_config(content: &str) -> Result<clash::Config> {
        // Try to parse as YAML
        if let Ok(config) = serde_yaml::from_str::<clash::Config>(content) {
            return Ok(config);
        }

        Err(ConvertError::ConfigValidationError(
            "Failed to parse Clash configuration".to_string(),
        ))
    }

    /// Parse Sing-box configuration (strongly typed)
    fn parse_singbox_config(content: &str) -> Result<singbox::Config> {
        // Try to parse as JSON first
        if let Ok(config) = serde_json::from_str::<singbox::Config>(content) {
            return Ok(config);
        }

        Err(ConvertError::ConfigValidationError(
            "Failed to parse Sing-box configuration".to_string(),
        ))
    }

    /// Parse V2Ray configuration (strongly typed)
    fn parse_v2ray_config(content: &str) -> Result<v2ray::Config> {
        // Try to parse as JSON first
        if let Ok(config) = serde_json::from_str::<v2ray::Config>(content) {
            return Ok(config);
        }

        Err(ConvertError::ConfigValidationError(
            "Failed to parse V2Ray configuration".to_string(),
        ))
    }
}
