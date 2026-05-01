//! Source loader for loading and parsing configurations.

use crate::core::config::AppConfig;
use crate::core::error::{ConvertError, NetworkErrorKind, Result};
use crate::core::source::{Protocol, SourceLocation, SourceMeta};
use crate::protocols::source::{Config, Source};
use crate::protocols::{ProtocolRegistry, FORMAT_PLAIN, FORMAT_SUBSCRIPTION};
use std::str::FromStr;
use std::time::Duration;
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
        match &source_meta.location {
            SourceLocation::Url(url) => {
                let url_with_flag = with_flag_param(
                    url.clone(),
                    source_meta.source_type,
                    source_meta.flag.as_deref(),
                );
                // Subscription panels (v2board/xboard/sspanel) route responses by UA.
                // Pick a protocol-matched default so the request isn't silently dropped.
                let ua = effective_user_agent(source_meta.source_type, source_meta.flag.as_deref(), config);
                Self::load_from_url(url_with_flag.as_str(), &ua, config).await
            }
            SourceLocation::File(path) => Self::load_from_file(path),
        }
    }

    async fn load_from_url(url: &str, user_agent: &str, config: &AppConfig) -> Result<String> {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(config.timeout_seconds))
            .user_agent(user_agent)
            .build()
            .map_err(|e| ConvertError::network(NetworkErrorKind::Other, Some(url.into()), e.to_string()))?;

        // Retry transient failures (timeout / connect / 5xx / 429). Attempts
        // cap at `config.retry_count + 1` total (first try + N retries).
        let mut attempt: u32 = 0;
        let max_attempts = config.retry_count.saturating_add(1);
        loop {
            attempt += 1;
            tracing::info!(
                "Fetching URL (attempt {}/{}): {} (UA: {})",
                attempt, max_attempts, url, user_agent
            );
            match fetch_once(&client, url).await {
                Ok(body) => return Ok(body),
                Err(err) => {
                    let retryable = matches!(&err,
                        ConvertError::NetworkError { kind, .. } if kind.is_retryable());
                    if !retryable || attempt >= max_attempts {
                        return Err(err);
                    }
                    // Exponential backoff: 250ms, 500ms, 1000ms, capped at 4s.
                    let backoff = Duration::from_millis(
                        (250u64 * (1u64 << (attempt - 1).min(4))).min(4000),
                    );
                    tracing::warn!(
                        "Fetch attempt {} failed ({}), retrying after {:?}",
                        attempt, err, backoff
                    );
                    tokio::time::sleep(backoff).await;
                }
            }
        }
    }

    fn load_from_file(path: &std::path::Path) -> Result<String> {
        if !path.exists() {
            return Err(ConvertError::file_not_found(&path.display().to_string()));
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

/// Perform a single HTTP GET, translating reqwest errors into a classified
/// `ConvertError::NetworkError` so retry logic and user-facing hints can act
/// on the kind.
async fn fetch_once(client: &reqwest::Client, url: &str) -> Result<String> {
    let response = client.get(url).send().await.map_err(|e| {
        let kind = if e.is_timeout() {
            NetworkErrorKind::Timeout
        } else if e.is_connect() {
            NetworkErrorKind::Connect
        } else {
            NetworkErrorKind::Other
        };
        ConvertError::network(kind, Some(url.into()), e.to_string())
    })?;

    let status = response.status();
    if !status.is_success() {
        return Err(ConvertError::network(
            NetworkErrorKind::Status(status.as_u16()),
            Some(url.into()),
            format!("HTTP {}", status),
        ));
    }

    response
        .text()
        .await
        .map_err(|e| ConvertError::network(NetworkErrorKind::Other, Some(url.into()), e.to_string()))
}

/// Choose the User-Agent to send with subscription requests.
/// Precedence: explicit `config.user_agent` (non-empty) > protocol-matched default.
fn effective_user_agent(source_type: Protocol, flag_override: Option<&str>, config: &AppConfig) -> String {
    let ua = config.user_agent.trim();
    if !ua.is_empty() {
        return ua.to_string();
    }
    let kind = flag_override
        .and_then(|s| Protocol::from_str(s).ok())
        .unwrap_or(source_type);
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
fn with_flag_param(mut url: Url, protocol: Protocol, flag_override: Option<&str>) -> Url {
    let flag_value = flag_override
        .map(|s| s.to_string())
        .unwrap_or_else(|| default_flag_for(protocol).to_string());

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
    url
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(u: &str) -> Url {
        Url::parse(u).unwrap()
    }

    #[test]
    fn adds_flag_when_absent() {
        let out = with_flag_param(parse("https://example.com/sub"), Protocol::SingBox, None);
        assert!(out.as_str().contains("flag=sing-box"));
    }

    #[test]
    fn replaces_existing_flag() {
        let out = with_flag_param(
            parse("https://example.com/sub?token=abc&flag=clash"),
            Protocol::SingBox,
            None,
        );
        let s = out.as_str();
        assert!(s.contains("token=abc"));
        assert!(s.contains("flag=sing-box"));
        assert!(!s.contains("flag=clash"));
    }

    #[test]
    fn override_wins_over_protocol_default() {
        let out = with_flag_param(parse("https://example.com/sub"), Protocol::Clash, Some("custom"));
        assert!(out.as_str().contains("flag=custom"));
    }

    #[test]
    fn preserves_fragment() {
        let out = with_flag_param(parse("https://example.com/sub#frag"), Protocol::V2Ray, None);
        let s = out.as_str();
        assert!(s.contains("flag=v2ray"));
        assert!(s.ends_with("#frag"));
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
        assert_eq!(
            effective_user_agent(Protocol::SingBox, Some("v2ray"), &cfg),
            "v2rayN"
        );
    }
}
