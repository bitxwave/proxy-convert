//! Protocol Module - Handle conversion between different proxy configuration formats

pub mod clash;
pub mod singbox;
pub mod v2ray;

use crate::utils::error::Result;
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

/// Protocol processor trait - each protocol should implement this
pub trait ProtocolProcessor {
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

/// Protocol converter registry
pub struct ProtocolRegistry {}

impl ProtocolRegistry {
    /// Create new registry
    pub fn new() -> Self {
        Self {}
    }

    /// Get converter
    pub fn get(&self, _name: &str) -> Option<&(dyn std::any::Any + Send + Sync)> {
        None
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
            _ => Err(crate::utils::error::ConvertError::ConfigValidationError(
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
            _ => Err(crate::utils::error::ConvertError::ConfigValidationError(
                format!("Unsupported input format: {}", format),
            )),
        }
    }

    /// Auto-detect input format
    pub fn auto_detect_format(&self, content: &str) -> Result<Option<(String, String)>> {
        let content = content.trim();

        // 尝试解析为 JSON
        if let Ok(json_value) = serde_json::from_str::<serde_json::Value>(content) {
            // 检查是否是 Clash 格式
            if Self::is_clash_format(&json_value) {
                return Ok(Some((
                    "clash".to_string(),
                    "Clash configuration".to_string(),
                )));
            }

            // 检查是否是 Sing-box 格式
            if Self::is_singbox_format(&json_value) {
                return Ok(Some((
                    "singbox".to_string(),
                    "Sing-box configuration".to_string(),
                )));
            }

            // 检查是否是 V2Ray 格式
            if Self::is_v2ray_format(&json_value) {
                return Ok(Some((
                    "v2ray".to_string(),
                    "V2Ray configuration".to_string(),
                )));
            }
        }

        // 尝试解析为 YAML
        if let Ok(yaml_value) = serde_yaml::from_str::<serde_json::Value>(content) {
            // 检查是否是 Clash 格式
            if Self::is_clash_format(&yaml_value) {
                return Ok(Some((
                    "clash".to_string(),
                    "Clash configuration (YAML)".to_string(),
                )));
            }

            // 检查是否是 Sing-box 格式
            if Self::is_singbox_format(&yaml_value) {
                return Ok(Some((
                    "singbox".to_string(),
                    "Sing-box configuration (YAML)".to_string(),
                )));
            }

            // 检查是否是 V2Ray 格式
            if Self::is_v2ray_format(&yaml_value) {
                return Ok(Some((
                    "v2ray".to_string(),
                    "V2Ray configuration (YAML)".to_string(),
                )));
            }
        }

        // 检查是否是订阅链接格式（base64 编码的配置）
        if Self::is_subscription_format(content) {
            return Ok(Some((
                "subscription".to_string(),
                "Subscription format (base64)".to_string(),
            )));
        }

        // 检查是否是纯文本格式（每行一个代理服务器）
        if Self::is_plain_text_format(content) {
            return Ok(Some(("plain".to_string(), "Plain text format".to_string())));
        }

        Ok(None)
    }

    /// Check if JSON value is Clash format
    fn is_clash_format(json: &serde_json::Value) -> bool {
        // Clash 格式特征：
        // 1. 有 "port" 字段
        // 2. 有 "socks-port" 字段
        // 3. 有 "proxies" 数组
        // 4. 有 "proxy-groups" 数组
        // 5. 有 "mixed-port" 字段（Clash 特有）
        // 6. 有 "external-controller" 字段（Clash 特有）
        json.get("port").is_some()
            || json.get("socks-port").is_some()
            || json.get("mixed-port").is_some()
            || json.get("external-controller").is_some()
            || json.get("proxies").is_some()
            || json.get("proxy-groups").is_some()
    }

    /// Check if JSON value is Sing-box format
    fn is_singbox_format(json: &serde_json::Value) -> bool {
        // Sing-box 格式特征：
        // 1. 有 "log" 字段
        // 2. 有 "inbounds" 数组
        // 3. 有 "outbounds" 数组
        // 4. 有 "route" 字段
        // 5. 有 "experimental" 字段（Sing-box 特有）
        // 6. 有 "dns" 字段（Sing-box 特有）
        let has_singbox_fields = json.get("experimental").is_some()
            || json.get("dns").is_some()
            || json.get("route").is_some();

        // 检查是否有 Sing-box 特有的字段，或者同时有 log、inbounds、outbounds 但没有 routing
        has_singbox_fields
            || (
                json.get("log").is_some()
                    && json.get("inbounds").is_some()
                    && json.get("outbounds").is_some()
                    && json.get("routing").is_none()
                // V2Ray 有 routing，Sing-box 有 route
            )
    }

    /// Check if JSON value is V2Ray format
    fn is_v2ray_format(json: &serde_json::Value) -> bool {
        // V2Ray 格式特征：
        // 1. 有 "log" 字段
        // 2. 有 "inbounds" 数组
        // 3. 有 "outbounds" 数组
        // 4. 有 "routing" 字段（V2Ray 特有）
        // 5. 有 "api" 字段（V2Ray 特有）
        // 6. 有 "stats" 字段（V2Ray 特有）
        let has_v2ray_fields = json.get("routing").is_some()
            || json.get("api").is_some()
            || json.get("stats").is_some();

        // 检查是否有 V2Ray 特有的字段，或者同时有 log、inbounds、outbounds 和 routing
        has_v2ray_fields
            || (
                json.get("log").is_some()
                    && json.get("inbounds").is_some()
                    && json.get("outbounds").is_some()
                    && json.get("routing").is_some()
                // V2Ray 有 routing
            )
    }

    /// Check if content is subscription format
    fn is_subscription_format(content: &str) -> bool {
        // 订阅格式特征：
        // 1. 以 vmess://, trojan://, ss:// 等协议开头
        // 2. 或者是 base64 编码的字符串
        content.starts_with("vmess://")
            || content.starts_with("trojan://")
            || content.starts_with("ss://")
            || content.starts_with("ssr://")
            || content.starts_with("http://")
            || content.starts_with("https://")
            || Self::is_base64_encoded(content)
    }

    /// Check if content is plain text format
    fn is_plain_text_format(content: &str) -> bool {
        // 纯文本格式特征：
        // 1. 每行一个代理服务器配置
        // 2. 包含协议标识符
        let lines: Vec<&str> = content.lines().collect();
        if lines.len() < 2 {
            return false;
        }

        // 检查前几行是否包含协议标识符
        lines.iter().take(3).any(|line| {
            let line = line.trim();
            !line.is_empty()
                && !line.starts_with('#')
                && (line.starts_with("vmess://")
                    || line.starts_with("trojan://")
                    || line.starts_with("ss://")
                    || line.starts_with("ssr://")
                    || line.starts_with("http://")
                    || line.starts_with("https://"))
        })
    }

    /// Check if string is base64 encoded
    fn is_base64_encoded(s: &str) -> bool {
        // 简单的 base64 检测：
        // 1. 移除空白字符后检查
        // 2. 长度是 4 的倍数
        // 3. 只包含 base64 字符
        let trimmed: String = s.chars().filter(|c| !c.is_whitespace()).collect();
        if trimmed.is_empty() || trimmed.len() % 4 != 0 {
            return false;
        }

        let base64_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";
        trimmed.chars().all(|c| base64_chars.contains(c))
    }

    /// Initialize protocol registry
    pub fn init() -> Self {
        let registry = Self::new();

        // Register various protocol converters
        // TODO: Register specific protocol converters here

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

        Err(crate::utils::error::ConvertError::ConfigValidationError(
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

        Err(crate::utils::error::ConvertError::ConfigValidationError(
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

        Err(crate::utils::error::ConvertError::ConfigValidationError(
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

        Err(crate::utils::error::ConvertError::ConfigValidationError(
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

        Err(crate::utils::error::ConvertError::ConfigValidationError(
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

        Err(crate::utils::error::ConvertError::ConfigValidationError(
            "Failed to parse V2Ray configuration".to_string(),
        ))
    }

    /// Parse subscription format configuration
    fn parse_subscription_format(&self, content: &str) -> Result<Vec<ProxyServer>> {
        tracing::info!("Parsing subscription format configuration");

        // Check if it's base64 encoded
        if Self::is_base64_encoded(content) {
            // Remove whitespace before decoding
            let clean_content: String = content.chars().filter(|c| !c.is_whitespace()).collect();
            if let Ok(decoded) =
                base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &clean_content)
            {
                if let Ok(decoded_str) = String::from_utf8(decoded) {
                    return self.parse_subscription_content(&decoded_str);
                }
            }
        }

        // Parse as plain text
        self.parse_subscription_content(content)
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

    /// Parse plain text format configuration
    fn parse_plain_text_format(&self, content: &str) -> Result<Vec<ProxyServer>> {
        tracing::info!("Parsing plain text format configuration");
        self.parse_subscription_content(content)
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
                return Err(crate::utils::error::ConvertError::ConfigValidationError(
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

    /// Public method to parse subscription format
    pub fn parse_subscription_format_pub(&self, content: &str) -> Result<Vec<ProxyServer>> {
        self.parse_subscription_format(content)
    }

    /// Public method to parse plain text format
    pub fn parse_plain_text_format_pub(&self, content: &str) -> Result<Vec<ProxyServer>> {
        self.parse_plain_text_format(content)
    }

    /// Parse subscription content (base64 decoded or plain text)
    fn parse_subscription_content(&self, content: &str) -> Result<Vec<ProxyServer>> {
        let mut servers = Vec::new();
        let lines: Vec<&str> = content.lines().collect();

        for line in lines {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            if let Some(server) = self.parse_proxy_url(line)? {
                servers.push(server);
            }
        }

        Ok(servers)
    }

    /// Parse proxy URL (vmess://, trojan://, ss://, etc.)
    fn parse_proxy_url(&self, url: &str) -> Result<Option<ProxyServer>> {
        if url.starts_with("vmess://") {
            self.parse_vmess_url(url)
        } else if url.starts_with("trojan://") {
            self.parse_trojan_url(url)
        } else if url.starts_with("ss://") {
            self.parse_shadowsocks_url(url)
        } else {
            tracing::warn!("Unsupported proxy URL: {}", url);
            Ok(None)
        }
    }

    /// Parse vmess:// URL
    fn parse_vmess_url(&self, url: &str) -> Result<Option<ProxyServer>> {
        // vmess://uuid@server:port?alterId=0&security=tls#name
        let vmess_part = url.strip_prefix("vmess://").unwrap_or("");
        if let Some(at_pos) = vmess_part.find('@') {
            let uuid = &vmess_part[..at_pos];
            let rest = &vmess_part[at_pos + 1..];

            if let Some(hash_pos) = rest.find('#') {
                let name = &rest[hash_pos + 1..];
                let server_port = &rest[..hash_pos];

                if let Some(colon_pos) = server_port.find(':') {
                    let server = &server_port[..colon_pos];
                    let port = server_port[colon_pos + 1..].parse::<u16>().unwrap_or(0);

                    let mut parameters = HashMap::new();
                    parameters.insert(
                        "uuid".to_string(),
                        serde_json::Value::String(uuid.to_string()),
                    );

                    Ok(Some(ProxyServer {
                        name: name.to_string(),
                        protocol: "vmess".to_string(),
                        server: server.to_string(),
                        port,
                        password: None,
                        method: None,
                        parameters,
                    }))
                } else {
                    Ok(None)
                }
            } else {
                Ok(None)
            }
        } else {
            Ok(None)
        }
    }

    /// Parse trojan:// URL
    fn parse_trojan_url(&self, url: &str) -> Result<Option<ProxyServer>> {
        // trojan://password@server:port?security=tls&sni=example.com#name
        let trojan_part = url.strip_prefix("trojan://").unwrap_or("");
        if let Some(at_pos) = trojan_part.find('@') {
            let password = &trojan_part[..at_pos];
            let rest = &trojan_part[at_pos + 1..];

            if let Some(hash_pos) = rest.find('#') {
                let name = &rest[hash_pos + 1..];
                let server_port = &rest[..hash_pos];

                if let Some(colon_pos) = server_port.find(':') {
                    let server = &server_port[..colon_pos];
                    let port = server_port[colon_pos + 1..].parse::<u16>().unwrap_or(0);

                    let mut parameters = HashMap::new();
                    parameters.insert(
                        "password".to_string(),
                        serde_json::Value::String(password.to_string()),
                    );

                    Ok(Some(ProxyServer {
                        name: name.to_string(),
                        protocol: "trojan".to_string(),
                        server: server.to_string(),
                        port,
                        password: Some(password.to_string()),
                        method: None,
                        parameters,
                    }))
                } else {
                    Ok(None)
                }
            } else {
                Ok(None)
            }
        } else {
            Ok(None)
        }
    }

    /// Parse ss:// URL (supports both legacy and SIP002 formats)
    fn parse_shadowsocks_url(&self, url: &str) -> Result<Option<ProxyServer>> {
        let ss_part = url.strip_prefix("ss://").unwrap_or("");

        // Extract name (URL encoded, after #)
        let (main_part, name) = if let Some(hash_pos) = ss_part.find('#') {
            let name_encoded = &ss_part[hash_pos + 1..];
            // URL decode the name
            let name = urlencoding::decode(name_encoded)
                .unwrap_or_else(|_| std::borrow::Cow::Borrowed(name_encoded))
                .to_string();
            (&ss_part[..hash_pos], name)
        } else {
            (ss_part, String::new())
        };

        // Remove query parameters if present
        let main_part = main_part.split('?').next().unwrap_or(main_part);

        // Check for SIP002 format: BASE64(method:password)@server:port
        if let Some(at_pos) = main_part.rfind('@') {
            let encoded = &main_part[..at_pos];
            let server_port = &main_part[at_pos + 1..];

            // Parse server:port
            let (server, port) = if let Some(colon_pos) = server_port.rfind(':') {
                let server = &server_port[..colon_pos];
                let port = server_port[colon_pos + 1..].parse::<u16>().unwrap_or(0);
                (server.to_string(), port)
            } else {
                return Ok(None);
            };

            // Decode base64 credentials (method:password)
            // Try standard base64 first, then URL-safe base64
            let decoded_result = base64::Engine::decode(
                &base64::engine::general_purpose::STANDARD,
                encoded,
            )
            .or_else(|_| {
                base64::Engine::decode(&base64::engine::general_purpose::URL_SAFE, encoded)
            })
            .or_else(|_| {
                // Try with padding
                let padded = match encoded.len() % 4 {
                    2 => format!("{}==", encoded),
                    3 => format!("{}=", encoded),
                    _ => encoded.to_string(),
                };
                base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &padded)
            });

            if let Ok(decoded) = decoded_result {
                if let Ok(decoded_str) = String::from_utf8(decoded) {
                    if let Some(colon_pos) = decoded_str.find(':') {
                        let method = &decoded_str[..colon_pos];
                        let password = &decoded_str[colon_pos + 1..];

                        return Ok(Some(ProxyServer {
                            name,
                            protocol: "shadowsocks".to_string(),
                            server,
                            port,
                            password: Some(password.to_string()),
                            method: Some(method.to_string()),
                            parameters: HashMap::new(),
                        }));
                    }
                }
            }
        }

        // Legacy format: base64(method:password@server:port)
        if let Ok(decoded) =
            base64::Engine::decode(&base64::engine::general_purpose::STANDARD, main_part)
        {
            if let Ok(decoded_str) = String::from_utf8(decoded) {
                if let Some(at_pos) = decoded_str.find('@') {
                    let method_password = &decoded_str[..at_pos];
                    let server_port = &decoded_str[at_pos + 1..];

                    if let Some(colon_pos) = method_password.find(':') {
                        let method = &method_password[..colon_pos];
                        let password = &method_password[colon_pos + 1..];

                        if let Some(colon_pos) = server_port.find(':') {
                            let server = &server_port[..colon_pos];
                            let port = server_port[colon_pos + 1..].parse::<u16>().unwrap_or(0);

                            return Ok(Some(ProxyServer {
                                name,
                                protocol: "shadowsocks".to_string(),
                                server: server.to_string(),
                                port,
                                password: Some(password.to_string()),
                                method: Some(method.to_string()),
                                parameters: HashMap::new(),
                            }));
                        }
                    }
                }
            }
        }

        Ok(None)
    }
}

impl Default for ProtocolRegistry {
    fn default() -> Self {
        Self::new()
    }
}
