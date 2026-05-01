//! Source loader for loading and parsing configurations.

use crate::core::config::AppConfig;
use crate::core::error::{ConvertError, Result};
use crate::core::source::{Protocol, SourceMeta};
use crate::protocols::{ProtocolRegistry, FORMAT_PLAIN, FORMAT_SUBSCRIPTION};
use crate::protocols::source::{Config, Source};
use std::path::Path;
use std::str::FromStr;
use url::Url;

pub struct SourceLoader;

impl SourceLoader {
    /// Load and parse a source configuration.
    pub async fn load_source(
        source_meta: &SourceMeta,
        registry: &ProtocolRegistry,
        config: &AppConfig,
    ) -> Result<Source> {
        let content = Self::load_content_from_source(source_meta, config).await?;

        let detected_format = source_meta
            .format
            .clone()
            .unwrap_or_else(|| source_meta.source_type.as_format_str().to_string());

        let parsed_config = Self::parse_config(&content, &detected_format, registry)?;

        Ok(Source::new(source_meta.clone(), parsed_config))
    }

    async fn load_content_from_source(
        source_meta: &SourceMeta,
        config: &AppConfig,
    ) -> Result<String> {
        let source = &source_meta.source;
        if source.starts_with("http://") || source.starts_with("https://") {
            let url_with_flag = with_flag_param(
                source,
                source_meta.source_type,
                source_meta.flag.as_deref(),
            )?;
            // Subscription panels (v2board/xboard/sspanel) route responses by UA.
            // Pick a protocol-matched default so the request isn't silently dropped.
            let ua = effective_user_agent(source_meta.source_type, source_meta.flag.as_deref(), config);
            Self::load_from_url(&url_with_flag, &ua, config).await
        } else {
            // File path: drop any query string that was kept on `source` for reference.
            let path = source.find('?').map(|i| &source[..i]).unwrap_or(source.as_str());
            Self::load_from_file(path)
        }
    }

    async fn load_from_url(url: &str, user_agent: &str, config: &AppConfig) -> Result<String> {
        tracing::info!("Fetching URL: {} (UA: {})", url, user_agent);

        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(config.timeout_seconds))
            .user_agent(user_agent)
            .build()
            .map_err(|e| ConvertError::network_error(&e.to_string()))?;

        let response = client
            .get(url)
            .send()
            .await
            .map_err(|e| ConvertError::network_error(&e.to_string()))?;

        if !response.status().is_success() {
            return Err(ConvertError::network_error(&format!(
                "Failed to fetch URL: {} - Status: {}",
                url,
                response.status()
            )));
        }

        response
            .text()
            .await
            .map_err(|e| ConvertError::network_error(&e.to_string()))
    }

    fn load_from_file(file_path: &str) -> Result<String> {
        let path = Path::new(file_path);
        if !path.exists() {
            return Err(ConvertError::file_not_found(file_path));
        }
        Ok(std::fs::read_to_string(path)?)
    }

    fn parse_config(content: &str, format: &str, registry: &ProtocolRegistry) -> Result<Config> {
        match format.to_lowercase().as_str() {
            FORMAT_SUBSCRIPTION => Ok(Config::Subscription(
                registry.parse_subscription_to_servers(content)?,
            )),
            FORMAT_PLAIN => Ok(Config::Plain(registry.parse_plain_text_to_servers(content)?)),
            other => {
                let fmt = registry.get_format(other).ok_or_else(|| {
                    ConvertError::ConfigValidationError(format!("Unsupported format: {}", other))
                })?;
                fmt.parse_config(content)
            }
        }
    }
}

/// Choose the User-Agent to send with subscription requests.
/// Precedence: explicit `config.user_agent` (non-empty) > protocol-matched default.
fn effective_user_agent(source_type: Protocol, flag_override: Option<&str>, config: &AppConfig) -> String {
    let ua = config.user_agent.trim();
    if !ua.is_empty() {
        return ua.to_string();
    }
    // Derive from flag if the user overrode it, otherwise from source_type.
    let kind = flag_override
        .and_then(|s| Protocol::from_str(s).ok())
        .unwrap_or(source_type);
    // Name-only; subscription panels typically match on the keyword, not the version.
    // Users who hit a version-strict panel can override via config.user_agent.
    match kind {
        Protocol::SingBox => "sing-box".to_string(),
        Protocol::Clash => "mihomo".to_string(),
        Protocol::V2Ray => "v2rayN".to_string(),
    }
}

/// Compute the panel's `flag` query param: explicit override wins; otherwise
/// derive from the source protocol (sing-box uses the hyphenated form).
fn default_flag_for(protocol: Protocol) -> &'static str {
    match protocol {
        Protocol::SingBox => "sing-box",
        Protocol::Clash => "clash",
        Protocol::V2Ray => "v2ray",
    }
}

/// Ensure the URL carries `flag=<value>`, replacing any existing value.
/// Uses `url::Url` so encoding, fragments, and other params round-trip cleanly.
fn with_flag_param(
    raw_url: &str,
    protocol: Protocol,
    flag_override: Option<&str>,
) -> Result<String> {
    let flag_value = flag_override
        .map(|s| s.to_string())
        .unwrap_or_else(|| default_flag_for(protocol).to_string());

    let mut url = Url::parse(raw_url)
        .map_err(|e| ConvertError::ConfigValidationError(format!("Invalid URL {}: {}", raw_url, e)))?;

    // Preserve every param except `flag`, then append the new flag.
    let preserved: Vec<(String, String)> = url
        .query_pairs()
        .filter(|(k, _)| k != "flag")
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect();
    url.query_pairs_mut().clear();
    for (k, v) in preserved {
        url.query_pairs_mut().append_pair(&k, &v);
    }
    url.query_pairs_mut().append_pair("flag", &flag_value);

    Ok(url.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn adds_flag_when_absent() {
        let out = with_flag_param("https://example.com/sub", Protocol::SingBox, None).unwrap();
        assert!(out.contains("flag=sing-box"));
    }

    #[test]
    fn replaces_existing_flag() {
        let out = with_flag_param(
            "https://example.com/sub?token=abc&flag=clash",
            Protocol::SingBox,
            None,
        )
        .unwrap();
        assert!(out.contains("token=abc"));
        assert!(out.contains("flag=sing-box"));
        assert!(!out.contains("flag=clash"));
    }

    #[test]
    fn override_wins_over_protocol_default() {
        let out = with_flag_param("https://example.com/sub", Protocol::Clash, Some("custom"))
            .unwrap();
        assert!(out.contains("flag=custom"));
    }

    #[test]
    fn preserves_fragment() {
        let out = with_flag_param("https://example.com/sub#frag", Protocol::V2Ray, None).unwrap();
        assert!(out.contains("flag=v2ray"));
        assert!(out.ends_with("#frag"));
    }

    #[test]
    fn effective_ua_respects_config_override() {
        let mut cfg = AppConfig::default();
        cfg.user_agent = "custom/1.0".to_string();
        assert_eq!(effective_user_agent(Protocol::Clash, None, &cfg), "custom/1.0");
    }

    #[test]
    fn effective_ua_falls_back_to_protocol_default() {
        let cfg = AppConfig::default();
        assert_eq!(effective_user_agent(Protocol::Clash, None, &cfg), "mihomo");
        assert_eq!(effective_user_agent(Protocol::SingBox, None, &cfg), "sing-box");
        assert_eq!(effective_user_agent(Protocol::V2Ray, None, &cfg), "v2rayN");
    }

    #[test]
    fn effective_ua_uses_flag_override_for_protocol_derivation() {
        let cfg = AppConfig::default();
        // Source is SingBox but flag override says v2ray → UA matches flag.
        assert_eq!(
            effective_user_agent(Protocol::SingBox, Some("v2ray"), &cfg),
            "v2rayN"
        );
    }
}
