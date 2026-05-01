//! Sing-box ProtocolFormat implementation.

use crate::core::error::{ConvertError, Result};
use crate::protocols::protocol_format::ProtocolFormat;
use crate::protocols::source::Config;
use crate::protocols::ProtocolProcessor;

use super::template_processor::SingboxProcessor;

/// Sing-box format descriptor.
pub struct SingboxFormat;

static PROCESSOR: SingboxProcessor = SingboxProcessor;

impl ProtocolFormat for SingboxFormat {
    fn name(&self) -> &'static str {
        "singbox"
    }

    fn aliases(&self) -> &'static [&'static str] {
        &["sing-box"]
    }

    fn config_ext(&self) -> &'static str {
        "json"
    }

    fn default_filename(&self) -> &'static str {
        "config.json"
    }

    fn default_template(&self) -> String {
        super::generate_default_template()
    }

    fn validate(&self, content: &str) -> Result<()> {
        let config: serde_json::Value = serde_json::from_str(content)?;
        if config.get("outbounds").is_none() {
            return Err(ConvertError::ConfigValidationError(
                "Missing required field 'outbounds' for Sing-box config".to_string(),
            ));
        }
        tracing::info!("Sing-box config structure is valid");
        Ok(())
    }

    fn parse_config(&self, content: &str) -> Result<Config> {
        Ok(Config::SingBox(parse_singbox_config(content)?))
    }

    fn processor(&self) -> &'static dyn ProtocolProcessor {
        &PROCESSOR
    }
}

/// Parse a sing-box config; normalizes legacy DNS servers that carry
/// `address` without a `type` field (older configs / Eternal Network style)
/// so they deserialize as `Server::Legacy`.
fn parse_singbox_config(content: &str) -> Result<super::Config> {
    if let Ok(config) =
        crate::utils::parse_helpers::from_json_or_yaml::<super::Config>(content)
    {
        return Ok(config);
    }
    if let Ok(mut value) = serde_json::from_str::<serde_json::Value>(content) {
        if let Some(dns) = value.get_mut("dns") {
            if let Some(servers) = dns.get_mut("servers").and_then(|s| s.as_array_mut()) {
                for server in servers {
                    if let Some(obj) = server.as_object_mut() {
                        if obj.contains_key("address") && !obj.contains_key("type") {
                            obj.insert("type".to_string(), serde_json::Value::String(String::new()));
                        }
                    }
                }
            }
        }
        if let Ok(config) = serde_json::from_value::<super::Config>(value) {
            return Ok(config);
        }
    }
    Err(ConvertError::ConfigValidationError(
        "Failed to parse Sing-box configuration".to_string(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocols::singbox::dns::Server as DnsServer;

    #[test]
    fn parse_legacy_dns_without_type() {
        let json = r#"{
            "dns": {
                "servers": [
                    {"address": "1.1.1.1", "detour": "proxy", "tag": "remote"},
                    {"address": "https://223.5.5.5/dns-query", "detour": "direct", "tag": "local"},
                    {"address": "rcode://refused", "tag": "block"}
                ],
                "final": "remote"
            },
            "inbounds": [],
            "outbounds": [{"type": "direct", "tag": "direct"}]
        }"#;
        let config = parse_singbox_config(json).unwrap();
        let dns = config.dns.as_ref().unwrap();
        assert_eq!(dns.servers.len(), 3);
        match &dns.servers[0] {
            DnsServer::Legacy(l) => {
                assert_eq!(l.address, "1.1.1.1");
                assert_eq!(l.tag.as_deref(), Some("remote"));
                assert_eq!(l.detour.as_deref(), Some("proxy"));
            }
            _ => panic!("first server should be Legacy"),
        }
        match &dns.servers[1] {
            DnsServer::Legacy(l) => assert_eq!(l.address, "https://223.5.5.5/dns-query"),
            _ => panic!("second server should be Legacy"),
        }
        match &dns.servers[2] {
            DnsServer::Legacy(l) => assert_eq!(l.address, "rcode://refused"),
            _ => panic!("third server should be Legacy"),
        }
    }
}
