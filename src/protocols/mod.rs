//! Protocol Module - Handle conversion between different proxy configuration formats.
//!
//! - **detect**: Format detection (clash/singbox/v2ray/subscription/plain).
//! - **subscription**: Parse subscription and plain-text proxy URLs.
//! - **Registry**: Holds ProtocolProcessors and delegates parsing to protocol submodules and subscription.

pub mod clash;
pub mod detect;
pub mod singbox;
pub mod subscription;
pub mod v2ray;

use crate::core::error::Result;
use crate::utils::source::parser::Source;
use crate::utils::template::interpolation_parser::InterpolationRule;
use indexmap::IndexMap;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Proxy server information
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProxyServer {
    /// Server name
    pub name: String,
    /// Server type
    pub protocol: String,
    /// Server address
    pub server: String,
    /// Server port
    pub port: u16,
    /// Password (if needed)
    pub password: Option<String>,
    /// Encryption method (if needed)
    pub method: Option<String>,
    /// Additional parameters
    pub parameters: HashMap<String, serde_json::Value>,
}

/// Protocol processor trait - each protocol implements this for template processing.
pub trait ProtocolProcessor: Send + Sync {
    /// Process interpolation rules for this protocol
    fn process_rule(
        &self,
        rule: &InterpolationRule,
        sources: &IndexMap<String, Source>,
    ) -> Result<String>;

    /// Get nodes for a specific rule
    fn get_nodes_for_rule(
        &self,
        rule: &InterpolationRule,
        sources: &IndexMap<String, Source>,
    ) -> Result<Vec<ProxyServer>>;

    /// Process default field values
    fn set_default_values(
        &self,
        template: &str,
        nodes: &[ProxyServer],
    ) -> Result<String>;

    /// Append nodes to the configuration
    fn append_nodes(
        &self,
        template: &str,
        nodes: &[ProxyServer],
    ) -> Result<String>;

    /// Create node configuration for this protocol
    fn create_node_config(&self, node: &ProxyServer) -> String;
}

/// Protocol converter registry: format detection, parsing, and processor lookup.
pub struct ProtocolRegistry {
    processors: HashMap<String, Box<dyn ProtocolProcessor>>,
}

impl ProtocolRegistry {
    /// Create new empty registry (for tests or custom setup).
    pub fn new() -> Self {
        Self {
            processors: HashMap::new(),
        }
    }

    /// Register a processor for a format name (e.g. "clash", "singbox", "v2ray").
    pub fn register(&mut self, format: &str, processor: Box<dyn ProtocolProcessor>) {
        self.processors.insert(format.to_lowercase(), processor);
    }

    /// Get processor by format name. Used by TemplateEngine.
    pub fn get_processor(&self, format: &str) -> Option<&dyn ProtocolProcessor> {
        self.processors.get(&format.to_lowercase()).map(|b| b.as_ref())
    }

    /// Parse content to ProxyServer list based on format
    pub fn parse_content(&self, content: &str, format: &str) -> Result<Vec<ProxyServer>> {
        tracing::info!("Parsing content with format: {}", format);

        match format.to_lowercase().as_str() {
            "clash" => self.parse_clash_format(content),
            "singbox" => self.parse_singbox_format(content),
            "v2ray" => self.parse_v2ray_format(content),
            "subscription" => self.parse_subscription_format(content),
            "plain" => self.parse_plain_text_format(content),
            _ => Err(crate::core::error::ConvertError::ConfigValidationError(
                format!("Unsupported input format: {}", format),
            )),
        }
    }

    /// Parse content to full configuration based on format
    pub fn parse_content_to_config(
        &self,
        content: &str,
        format: &str,
    ) -> Result<serde_json::Value> {
        tracing::info!("Parsing content to config with format: {}", format);

        match format.to_lowercase().as_str() {
            "clash" => self.parse_clash_config(content),
            "singbox" => self.parse_singbox_config(content),
            "v2ray" => self.parse_v2ray_config(content),
            "subscription" => self.parse_subscription_config(content),
            "plain" => self.parse_plain_text_config(content),
            _ => Err(crate::core::error::ConvertError::ConfigValidationError(
                format!("Unsupported input format: {}", format),
            )),
        }
    }

    /// Auto-detect input format (delegates to detect module).
    pub fn auto_detect_format(&self, content: &str) -> Result<Option<(String, String)>> {
        detect::detect_format(content)
    }

    /// Initialize protocol registry with built-in processors (clash, singbox, v2ray).
    pub fn init() -> Self {
        let mut registry = Self::new();
        registry.register("clash", Box::new(clash::template_processor::ClashProcessor));
        registry.register("singbox", Box::new(singbox::template_processor::SingboxProcessor));
        registry.register("v2ray", Box::new(v2ray::template_processor::V2RayProcessor));
        tracing::info!("Protocol registry initialized successfully");
        registry
    }

    /// Parse Clash format configuration
    fn parse_clash_format(&self, content: &str) -> Result<Vec<ProxyServer>> {
        tracing::info!("Parsing Clash format configuration");

        // Try to parse as JSON first
        if let Ok(config) = serde_json::from_str::<clash::Config>(content) {
            return self.convert_clash_config_to_servers(&config);
        }

        // Try to parse as YAML
        if let Ok(config) = serde_yaml::from_str::<clash::Config>(content) {
            return self.convert_clash_config_to_servers(&config);
        }

        Err(crate::core::error::ConvertError::ConfigValidationError(
            "Failed to parse Clash configuration".to_string(),
        ))
    }

    /// Parse Clash format configuration to JSON
    fn parse_clash_config(&self, content: &str) -> Result<serde_json::Value> {
        tracing::info!("Parsing Clash format configuration to JSON");

        // Try to parse as JSON first
        if let Ok(config) = serde_json::from_str::<serde_json::Value>(content) {
            return Ok(config);
        }

        // Try to parse as YAML
        if let Ok(config) = serde_yaml::from_str::<serde_json::Value>(content) {
            return Ok(config);
        }

        Err(crate::core::error::ConvertError::ConfigValidationError(
            "Failed to parse Clash configuration".to_string(),
        ))
    }

    /// Parse Sing-box format configuration
    fn parse_singbox_format(&self, content: &str) -> Result<Vec<ProxyServer>> {
        tracing::info!("Parsing Sing-box format configuration");

        // Try to parse as JSON first
        if let Ok(config) = serde_json::from_str::<serde_json::Value>(content) {
            return self.convert_singbox_config_to_servers(&config);
        }

        // Try to parse as YAML
        if let Ok(config) = serde_yaml::from_str::<serde_json::Value>(content) {
            return self.convert_singbox_config_to_servers(&config);
        }

        Err(crate::core::error::ConvertError::ConfigValidationError(
            "Failed to parse Sing-box configuration".to_string(),
        ))
    }

    /// Parse Sing-box format configuration to JSON
    fn parse_singbox_config(&self, content: &str) -> Result<serde_json::Value> {
        tracing::info!("Parsing Sing-box format configuration to JSON");

        // Try to parse as JSON first
        if let Ok(config) = serde_json::from_str::<serde_json::Value>(content) {
            return Ok(config);
        }

        // Try to parse as YAML
        if let Ok(config) = serde_yaml::from_str::<serde_json::Value>(content) {
            return Ok(config);
        }

        Err(crate::core::error::ConvertError::ConfigValidationError(
            "Failed to parse Sing-box configuration".to_string(),
        ))
    }

    /// Parse V2Ray format configuration
    fn parse_v2ray_format(&self, content: &str) -> Result<Vec<ProxyServer>> {
        tracing::info!("Parsing V2Ray format configuration");

        // Try to parse as JSON first
        if let Ok(config) = serde_json::from_str::<serde_json::Value>(content) {
            return self.convert_v2ray_config_to_servers(&config);
        }

        // Try to parse as YAML
        if let Ok(config) = serde_yaml::from_str::<serde_json::Value>(content) {
            return self.convert_v2ray_config_to_servers(&config);
        }

        Err(crate::core::error::ConvertError::ConfigValidationError(
            "Failed to parse V2Ray configuration".to_string(),
        ))
    }

    /// Parse V2Ray format configuration to JSON
    fn parse_v2ray_config(&self, content: &str) -> Result<serde_json::Value> {
        tracing::info!("Parsing V2Ray format configuration to JSON");

        // Try to parse as JSON first
        if let Ok(config) = serde_json::from_str::<serde_json::Value>(content) {
            return Ok(config);
        }

        // Try to parse as YAML
        if let Ok(config) = serde_yaml::from_str::<serde_json::Value>(content) {
            return Ok(config);
        }

        Err(crate::core::error::ConvertError::ConfigValidationError(
            "Failed to parse V2Ray configuration".to_string(),
        ))
    }

    /// Parse subscription format (delegates to subscription module).
    fn parse_subscription_format(&self, content: &str) -> Result<Vec<ProxyServer>> {
        tracing::info!("Parsing subscription format configuration");
        subscription::parse_subscription(content)
    }

    /// Parse subscription format configuration to JSON
    fn parse_subscription_config(&self, content: &str) -> Result<serde_json::Value> {
        tracing::info!("Parsing subscription format configuration to JSON");

        // For subscription format, we create a simple config with the servers
        let servers = self.parse_subscription_format(content)?;
        let config = serde_json::json!({
            "proxies": servers
        });
        Ok(config)
    }

    /// Parse plain text format (delegates to subscription module).
    fn parse_plain_text_format(&self, content: &str) -> Result<Vec<ProxyServer>> {
        tracing::info!("Parsing plain text format configuration");
        subscription::parse_plain_text(content)
    }

    /// Parse plain text format configuration to JSON
    fn parse_plain_text_config(&self, content: &str) -> Result<serde_json::Value> {
        tracing::info!("Parsing plain text format configuration to JSON");

        // For plain text format, we create a simple config with the servers
        let servers = self.parse_plain_text_format(content)?;
        let config = serde_json::json!({
            "proxies": servers
        });
        Ok(config)
    }

    /// Convert Clash config to ProxyServer list
    fn convert_clash_config_to_servers(&self, config: &clash::Config) -> Result<Vec<ProxyServer>> {
        let mut servers = Vec::new();

        for proxy in &config.proxies {
            let server = self.convert_clash_proxy_to_server(proxy)?;
            servers.push(server);
        }

        Ok(servers)
    }

    /// Convert Clash proxy to ProxyServer
    fn convert_clash_proxy_to_server(&self, proxy: &clash::proxy::Proxy) -> Result<ProxyServer> {
        let (protocol, server, port, password, method, parameters) = match proxy {
            clash::proxy::Proxy::Ss(ss) => {
                let mut params = HashMap::new();
                params.insert(
                    "cipher".to_string(),
                    serde_json::Value::String(ss.cipher.clone()),
                );
                if let Some(udp) = ss.udp {
                    params.insert("udp".to_string(), serde_json::Value::Bool(udp));
                }

                (
                    "shadowsocks".to_string(),
                    ss.server.clone(),
                    ss.port,
                    Some(ss.password.clone()),
                    Some(ss.cipher.clone()),
                    params,
                )
            }
            clash::proxy::Proxy::Vmess(vmess) => {
                let mut params = HashMap::new();
                if let Some(uuid) = &vmess.uuid {
                    params.insert("uuid".to_string(), serde_json::Value::String(uuid.clone()));
                }
                if let Some(alter_id) = vmess.alter_id {
                    params.insert(
                        "alterId".to_string(),
                        serde_json::Value::Number(serde_json::Number::from(alter_id)),
                    );
                }

                (
                    "vmess".to_string(),
                    vmess.server.clone(),
                    vmess.port,
                    None,
                    None,
                    params,
                )
            }
            clash::proxy::Proxy::Trojan(trojan) => {
                let mut params = HashMap::new();
                if let Some(password) = &trojan.password {
                    params.insert(
                        "password".to_string(),
                        serde_json::Value::String(password.clone()),
                    );
                }
                if let Some(sni) = &trojan.sni {
                    params.insert("sni".to_string(), serde_json::Value::String(sni.clone()));
                }

                (
                    "trojan".to_string(),
                    trojan.server.clone(),
                    trojan.port,
                    trojan.password.clone(),
                    None,
                    params,
                )
            }
            clash::proxy::Proxy::Socks5(socks5) => {
                let mut params = HashMap::new();
                if let Some(username) = &socks5.username {
                    params.insert(
                        "username".to_string(),
                        serde_json::Value::String(username.clone()),
                    );
                }
                if let Some(password) = &socks5.password {
                    params.insert(
                        "password".to_string(),
                        serde_json::Value::String(password.clone()),
                    );
                }

                (
                    "socks5".to_string(),
                    socks5.server.clone(),
                    socks5.port,
                    None,
                    None,
                    params,
                )
            }
            _ => {
                tracing::warn!("Unsupported Clash proxy type: {:?}", proxy);
                return Err(crate::core::error::ConvertError::ConfigValidationError(
                    format!("Unsupported Clash proxy type: {:?}", proxy),
                ));
            }
        };

        Ok(ProxyServer {
            name: proxy.name().to_string(),
            protocol,
            server,
            port,
            password,
            method,
            parameters,
        })
    }

    /// Convert Sing-box config to ProxyServer list
    fn convert_singbox_config_to_servers(
        &self,
        config: &serde_json::Value,
    ) -> Result<Vec<ProxyServer>> {
        let mut servers = Vec::new();

        if let Some(outbounds) = config.get("outbounds").and_then(|v| v.as_array()) {
            for outbound in outbounds {
                if let Some(server) = self.convert_singbox_outbound_to_server(outbound)? {
                    servers.push(server);
                }
            }
        }

        Ok(servers)
    }

    /// Convert Sing-box outbound to ProxyServer
    fn convert_singbox_outbound_to_server(
        &self,
        outbound: &serde_json::Value,
    ) -> Result<Option<ProxyServer>> {
        let outbound_type = outbound.get("type").and_then(|v| v.as_str()).unwrap_or("");

        match outbound_type {
            "shadowsocks" => {
                let name = outbound
                    .get("tag")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let server = outbound
                    .get("server")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let port = outbound.get("port").and_then(|v| v.as_u64()).unwrap_or(0) as u16;
                let password = outbound
                    .get("password")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());
                let method = outbound
                    .get("method")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());

                let mut parameters = HashMap::new();
                if let Some(udp) = outbound.get("udp") {
                    parameters.insert("udp".to_string(), udp.clone());
                }

                Ok(Some(ProxyServer {
                    name,
                    protocol: "shadowsocks".to_string(),
                    server,
                    port,
                    password,
                    method,
                    parameters,
                }))
            }
            "vmess" => {
                let name = outbound
                    .get("tag")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let server = outbound
                    .get("server")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let port = outbound.get("port").and_then(|v| v.as_u64()).unwrap_or(0) as u16;
                let uuid = outbound
                    .get("uuid")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();

                let mut parameters = HashMap::new();
                parameters.insert("uuid".to_string(), serde_json::Value::String(uuid));
                if let Some(security) = outbound.get("security") {
                    parameters.insert("security".to_string(), security.clone());
                }

                Ok(Some(ProxyServer {
                    name,
                    protocol: "vmess".to_string(),
                    server,
                    port,
                    password: None,
                    method: None,
                    parameters,
                }))
            }
            _ => {
                tracing::warn!("Unsupported Sing-box outbound type: {}", outbound_type);
                Ok(None)
            }
        }
    }

    /// Convert V2Ray config to ProxyServer list
    fn convert_v2ray_config_to_servers(
        &self,
        config: &serde_json::Value,
    ) -> Result<Vec<ProxyServer>> {
        let mut servers = Vec::new();

        if let Some(outbounds) = config.get("outbounds").and_then(|v| v.as_array()) {
            for outbound in outbounds {
                if let Some(server) = self.convert_v2ray_outbound_to_server(outbound)? {
                    servers.push(server);
                }
            }
        }

        Ok(servers)
    }

    /// Convert V2Ray outbound to ProxyServer
    fn convert_v2ray_outbound_to_server(
        &self,
        outbound: &serde_json::Value,
    ) -> Result<Option<ProxyServer>> {
        let protocol = outbound
            .get("protocol")
            .and_then(|v| v.as_str())
            .unwrap_or("");

        match protocol {
            "vmess" => {
                let name = outbound
                    .get("tag")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let settings = outbound
                    .get("settings")
                    .and_then(|v| v.get("vnext"))
                    .and_then(|v| v.as_array())
                    .and_then(|v| v.first())
                    .and_then(|v| v.get("users"))
                    .and_then(|v| v.as_array())
                    .and_then(|v| v.first());

                if let Some(user) = settings {
                    let uuid = user
                        .get("id")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string();
                    let alter_id = user.get("alterId").and_then(|v| v.as_u64()).unwrap_or(0);

                    let mut parameters = HashMap::new();
                    parameters.insert("uuid".to_string(), serde_json::Value::String(uuid));
                    parameters.insert(
                        "alterId".to_string(),
                        serde_json::Value::Number(serde_json::Number::from(alter_id)),
                    );

                    let stream_settings = outbound.get("streamSettings");
                    if let Some(security) = stream_settings.and_then(|v| v.get("security")) {
                        parameters.insert("security".to_string(), security.clone());
                    }

                    Ok(Some(ProxyServer {
                        name,
                        protocol: "vmess".to_string(),
                        server: "".to_string(), // V2Ray config doesn't have server in outbound
                        port: 0,                // V2Ray config doesn't have port in outbound
                        password: None,
                        method: None,
                        parameters,
                    }))
                } else {
                    Ok(None)
                }
            }
            _ => {
                tracing::warn!("Unsupported V2Ray protocol: {}", protocol);
                Ok(None)
            }
        }
    }

    /// Parse subscription format to ProxyServer list. Public API for SourceLoader.
    pub fn parse_subscription_to_servers(&self, content: &str) -> Result<Vec<ProxyServer>> {
        self.parse_subscription_format(content)
    }

    /// Parse plain text format to ProxyServer list. Public API for SourceLoader.
    pub fn parse_plain_text_to_servers(&self, content: &str) -> Result<Vec<ProxyServer>> {
        self.parse_plain_text_format(content)
    }
}

impl Default for ProtocolRegistry {
    fn default() -> Self {
        Self::new()
    }
}
