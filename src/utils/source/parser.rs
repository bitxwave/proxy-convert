//! Source configuration parser

use crate::commands::convert::SourceMeta;
use crate::protocols::{clash, singbox, v2ray, ProxyServer};
use crate::utils::error::Result;
use std::collections::HashMap;

/// Configuration for different protocols (strongly typed)
#[derive(Debug, Clone)]
pub enum Config {
    Clash(clash::Config),
    SingBox(singbox::Config),
    V2Ray(v2ray::Config),
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
            Config::Clash(config) => Self::extract_servers_from_clash_config(config),
            Config::SingBox(config) => Self::extract_servers_from_singbox_config(config),
            Config::V2Ray(config) => Self::extract_servers_from_v2ray_config(config),
            Config::Subscription(servers) => Ok(servers.clone()),
            Config::Plain(servers) => Ok(servers.clone()),
        }
    }

    /// Extract servers from Clash configuration (strongly typed)
    fn extract_servers_from_clash_config(config: &clash::Config) -> Result<Vec<ProxyServer>> {
        let mut servers = Vec::new();

        for proxy in &config.proxies {
            if let Some(server) = Self::parse_clash_proxy(proxy) {
                servers.push(server);
            }
        }

        Ok(servers)
    }

    /// Parse a single Clash proxy entry (strongly typed)
    fn parse_clash_proxy(proxy: &clash::proxy::Proxy) -> Option<ProxyServer> {
        // Convert Clash proxy to JSON for generic handling
        let proxy_json = serde_json::to_value(proxy).ok()?;

        let name = proxy_json.get("name")?.as_str()?.to_string();
        let mut protocol = proxy_json.get("type")?.as_str()?.to_string();

        // Normalize protocol names: clash uses "ss" but sing-box uses "shadowsocks"
        if protocol == "ss" {
            protocol = "shadowsocks".to_string();
        }

        let server = proxy_json.get("server")?.as_str()?.to_string();
        let port = proxy_json.get("port")?.as_u64()? as u16;

        let password = proxy_json
            .get("password")
            .and_then(|v| v.as_str())
            .map(String::from);
        let method = proxy_json
            .get("cipher")
            .or_else(|| proxy_json.get("method"))
            .and_then(|v| v.as_str())
            .map(String::from);

        // Collect additional parameters
        let mut parameters = HashMap::new();
        let skip_keys = [
            "name", "type", "server", "port", "password", "cipher", "method",
        ];

        if let Some(obj) = proxy_json.as_object() {
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

    /// Extract servers from Sing-box configuration (strongly typed)
    fn extract_servers_from_singbox_config(config: &singbox::Config) -> Result<Vec<ProxyServer>> {
        let mut servers = Vec::new();

        for outbound in &config.outbounds {
            if let Some(server) = Self::parse_singbox_outbound(outbound) {
                servers.push(server);
            }
        }

        Ok(servers)
    }

    /// Parse a single Sing-box outbound entry (strongly typed)
    fn parse_singbox_outbound(outbound: &singbox::outbound::Outbound) -> Option<ProxyServer> {
        // Convert outbound to JSON for generic handling
        let outbound_json = serde_json::to_value(outbound).ok()?;

        let outbound_type = outbound_json.get("type")?.as_str()?;

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

        let tag = outbound_json.get("tag")?.as_str()?.to_string();
        let server = outbound_json
            .get("server")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let port = outbound_json
            .get("server_port")
            .or_else(|| outbound_json.get("port"))
            .and_then(|v| v.as_u64())
            .unwrap_or(0) as u16;

        let password = outbound_json
            .get("password")
            .and_then(|v| v.as_str())
            .map(String::from);
        let method = outbound_json
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

        if let Some(obj) = outbound_json.as_object() {
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

    /// Extract servers from V2Ray configuration (strongly typed)
    fn extract_servers_from_v2ray_config(config: &v2ray::Config) -> Result<Vec<ProxyServer>> {
        let mut servers = Vec::new();

        for outbound in &config.outbounds {
            if let Some(server) = Self::parse_v2ray_outbound(outbound) {
                servers.push(server);
            }
        }

        Ok(servers)
    }

    /// Parse a single V2Ray outbound entry (strongly typed)
    fn parse_v2ray_outbound(outbound: &v2ray::Outbound) -> Option<ProxyServer> {
        let protocol = outbound.protocol.as_deref()?;

        // Skip non-proxy protocols
        let proxy_protocols = ["vmess", "vless", "trojan", "shadowsocks", "socks", "http"];

        if !proxy_protocols.contains(&protocol) {
            return None;
        }

        let tag = outbound.tag.clone().unwrap_or_default();

        // V2Ray has a more complex structure with settings.vnext or settings.servers
        let (server, port) = Self::extract_v2ray_server_info(outbound, protocol).unwrap_or_default();
        let password = Self::extract_v2ray_password(outbound, protocol);
        let method = Self::extract_v2ray_method(outbound, protocol);

        // Collect additional parameters from extra
        let mut parameters = HashMap::new();
        for (key, value) in &outbound.extra {
            parameters.insert(key.clone(), value.clone());
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
    fn extract_v2ray_server_info(outbound: &v2ray::Outbound, protocol: &str) -> Option<(String, u16)> {
        let settings = outbound.settings.as_ref()?;

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
    fn extract_v2ray_password(outbound: &v2ray::Outbound, protocol: &str) -> Option<String> {
        let settings = outbound.settings.as_ref()?;

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
    fn extract_v2ray_method(outbound: &v2ray::Outbound, protocol: &str) -> Option<String> {
        let settings = outbound.settings.as_ref()?;

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
