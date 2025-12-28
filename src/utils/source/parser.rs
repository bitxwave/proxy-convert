//! Source configuration parser

use crate::commands::convert::SourceMeta;
use crate::protocols::ProxyServer;
use crate::utils::error::Result;
use serde_json;
use std::collections::HashMap;

/// Configuration for different protocols
#[derive(Debug, Clone)]
pub enum Config {
    Clash(serde_json::Value),
    SingBox(serde_json::Value),
    V2Ray(serde_json::Value),
    /// Subscription format (parsed proxy servers)
    Subscription(Vec<ProxyServer>),
    /// Plain text format (parsed proxy servers)
    Plain(Vec<ProxyServer>),
}

/// Source information for template processing
#[derive(Debug, Clone)]
pub struct Source {
    pub meta: SourceMeta,
    pub config: Config,
}

impl Source {
    /// Create a new source
    pub fn new(meta: SourceMeta, config: Config) -> Self {
        Self { meta, config }
    }

    /// Extract servers from the configuration
    pub fn extract_servers(&self) -> Result<Vec<ProxyServer>> {
        match &self.config {
            Config::Clash(config_value) => self.extract_servers_from_clash_config(config_value),
            Config::SingBox(config_value) => self.extract_servers_from_singbox_config(config_value),
            Config::V2Ray(config_value) => self.extract_servers_from_v2ray_config(config_value),
            Config::Subscription(servers) => Ok(servers.clone()),
            Config::Plain(servers) => Ok(servers.clone()),
        }
    }

    /// Extract servers from Clash configuration
    fn extract_servers_from_clash_config(
        &self,
        config: &serde_json::Value,
    ) -> Result<Vec<ProxyServer>> {
        let mut servers = Vec::new();

        if let Some(proxies) = config.get("proxies").and_then(|v| v.as_array()) {
            for proxy in proxies {
                if let Some(server) = self.parse_clash_proxy(proxy) {
                    servers.push(server);
                }
            }
        }

        Ok(servers)
    }

    /// Parse a single Clash proxy entry
    fn parse_clash_proxy(&self, proxy: &serde_json::Value) -> Option<ProxyServer> {
        let name = proxy.get("name")?.as_str()?.to_string();
        let mut protocol = proxy.get("type")?.as_str()?.to_string();
        
        // Normalize protocol names: clash uses "ss" but sing-box uses "shadowsocks"
        if protocol == "ss" {
            protocol = "shadowsocks".to_string();
        }
        
        let server = proxy.get("server")?.as_str()?.to_string();
        let port = proxy.get("port")?.as_u64()? as u16;

        let password = proxy
            .get("password")
            .and_then(|v| v.as_str())
            .map(String::from);
        let method = proxy
            .get("cipher")
            .or_else(|| proxy.get("method"))
            .and_then(|v| v.as_str())
            .map(String::from);

        // Collect additional parameters
        let mut parameters = HashMap::new();
        let skip_keys = [
            "name", "type", "server", "port", "password", "cipher", "method",
        ];

        if let Some(obj) = proxy.as_object() {
            for (key, value) in obj {
                if !skip_keys.contains(&key.as_str()) {
                    parameters.insert(key.clone(), value.clone());
                }
            }
        }

        Some(ProxyServer {
            name,
            protocol,
            server,
            port,
            password,
            method,
            parameters,
        })
    }

    /// Extract servers from Sing-box configuration
    fn extract_servers_from_singbox_config(
        &self,
        config: &serde_json::Value,
    ) -> Result<Vec<ProxyServer>> {
        let mut servers = Vec::new();

        if let Some(outbounds) = config.get("outbounds").and_then(|v| v.as_array()) {
            for outbound in outbounds {
                if let Some(server) = self.parse_singbox_outbound(outbound) {
                    servers.push(server);
                }
            }
        }

        Ok(servers)
    }

    /// Parse a single Sing-box outbound entry
    fn parse_singbox_outbound(&self, outbound: &serde_json::Value) -> Option<ProxyServer> {
        let outbound_type = outbound.get("type")?.as_str()?;

        // Skip non-proxy outbound types
        let proxy_types = [
            "shadowsocks",
            "vmess",
            "vless",
            "trojan",
            "hysteria",
            "hysteria2",
            "shadowtls",
            "tuic",
            "wireguard",
            "ssh",
            "socks",
            "http",
        ];

        if !proxy_types.contains(&outbound_type) {
            return None;
        }

        let tag = outbound.get("tag")?.as_str()?.to_string();
        let server = outbound
            .get("server")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let port = outbound
            .get("server_port")
            .or_else(|| outbound.get("port"))
            .and_then(|v| v.as_u64())
            .unwrap_or(0) as u16;

        // Don't require server/port for all types (e.g., wireguard might use different fields)
        if server.is_empty() && port == 0 {
            // Still create a ProxyServer with just the tag/name for reference
        }

        let password = outbound
            .get("password")
            .and_then(|v| v.as_str())
            .map(String::from);
        let method = outbound
            .get("method")
            .and_then(|v| v.as_str())
            .map(String::from);

        // Collect additional parameters
        let mut parameters = HashMap::new();
        let skip_keys = [
            "type",
            "tag",
            "server",
            "server_port",
            "port",
            "password",
            "method",
        ];

        if let Some(obj) = outbound.as_object() {
            for (key, value) in obj {
                if !skip_keys.contains(&key.as_str()) {
                    parameters.insert(key.clone(), value.clone());
                }
            }
        }

        Some(ProxyServer {
            name: tag,
            protocol: outbound_type.to_string(),
            server,
            port,
            password,
            method,
            parameters,
        })
    }

    /// Extract servers from V2Ray configuration
    fn extract_servers_from_v2ray_config(
        &self,
        config: &serde_json::Value,
    ) -> Result<Vec<ProxyServer>> {
        let mut servers = Vec::new();

        if let Some(outbounds) = config.get("outbounds").and_then(|v| v.as_array()) {
            for outbound in outbounds {
                if let Some(server) = self.parse_v2ray_outbound(outbound) {
                    servers.push(server);
                }
            }
        }

        Ok(servers)
    }

    /// Parse a single V2Ray outbound entry
    fn parse_v2ray_outbound(&self, outbound: &serde_json::Value) -> Option<ProxyServer> {
        let protocol = outbound.get("protocol")?.as_str()?;

        // Skip non-proxy protocols
        let proxy_protocols = ["vmess", "vless", "trojan", "shadowsocks", "socks", "http"];

        if !proxy_protocols.contains(&protocol) {
            return None;
        }

        let tag = outbound
            .get("tag")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();

        // V2Ray has a more complex structure with settings.vnext or settings.servers
        let (server, port) = self
            .extract_v2ray_server_info(outbound, protocol)
            .unwrap_or_default();

        let password = self.extract_v2ray_password(outbound, protocol);
        let method = self.extract_v2ray_method(outbound, protocol);

        // Collect additional parameters
        let mut parameters = HashMap::new();
        if let Some(obj) = outbound.as_object() {
            for (key, value) in obj {
                if key != "protocol" && key != "tag" && key != "settings" {
                    parameters.insert(key.clone(), value.clone());
                }
            }
        }

        Some(ProxyServer {
            name: tag,
            protocol: protocol.to_string(),
            server,
            port,
            password,
            method,
            parameters,
        })
    }

    /// Extract server and port from V2Ray outbound
    fn extract_v2ray_server_info(
        &self,
        outbound: &serde_json::Value,
        protocol: &str,
    ) -> Option<(String, u16)> {
        let settings = outbound.get("settings")?;

        match protocol {
            "vmess" | "vless" => {
                let vnext = settings.get("vnext")?.as_array()?.first()?;
                let address = vnext.get("address")?.as_str()?.to_string();
                let port = vnext.get("port")?.as_u64()? as u16;
                Some((address, port))
            }
            "trojan" | "shadowsocks" | "socks" | "http" => {
                let servers = settings.get("servers")?.as_array()?.first()?;
                let address = servers.get("address")?.as_str()?.to_string();
                let port = servers.get("port")?.as_u64()? as u16;
                Some((address, port))
            }
            _ => None,
        }
    }

    /// Extract password from V2Ray outbound
    fn extract_v2ray_password(
        &self,
        outbound: &serde_json::Value,
        protocol: &str,
    ) -> Option<String> {
        let settings = outbound.get("settings")?;

        match protocol {
            "vmess" | "vless" => settings
                .get("vnext")?
                .as_array()?
                .first()?
                .get("users")?
                .as_array()?
                .first()?
                .get("id")
                .and_then(|v| v.as_str())
                .map(String::from),
            "trojan" => settings
                .get("servers")?
                .as_array()?
                .first()?
                .get("password")
                .and_then(|v| v.as_str())
                .map(String::from),
            "shadowsocks" => settings
                .get("servers")?
                .as_array()?
                .first()?
                .get("password")
                .and_then(|v| v.as_str())
                .map(String::from),
            _ => None,
        }
    }

    /// Extract method/cipher from V2Ray outbound
    fn extract_v2ray_method(&self, outbound: &serde_json::Value, protocol: &str) -> Option<String> {
        let settings = outbound.get("settings")?;

        match protocol {
            "shadowsocks" => settings
                .get("servers")?
                .as_array()?
                .first()?
                .get("method")
                .and_then(|v| v.as_str())
                .map(String::from),
            "vmess" => settings
                .get("vnext")?
                .as_array()?
                .first()?
                .get("users")?
                .as_array()?
                .first()?
                .get("security")
                .and_then(|v| v.as_str())
                .map(String::from),
            _ => None,
        }
    }
}
