//! Source configuration parser

use crate::core::source::SourceMeta;
use crate::core::error::Result;
use crate::protocols::{clash, singbox, v2ray, ProxyParams, ProxyServer, TlsParams, TransportParams};
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
        // Still serialize to JSON for the old parameters HashMap (backward compat)
        let proxy_json = match serde_json::to_value(proxy) {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!("Failed to serialize Clash proxy '{}': {}", proxy.name(), e);
                return None;
            }
        };

        // Extract typed params directly from the strong type
        let (params, protocol, password, method) = match proxy {
            clash::proxy::Proxy::Ss(ss) => (
                ProxyParams::Shadowsocks {
                    cipher: ss.cipher.clone(),
                    udp: ss.udp,
                    plugin: None,
                    plugin_opts: None,
                },
                "shadowsocks".to_string(),
                Some(ss.password.clone()),
                Some(ss.cipher.clone()),
            ),
            clash::proxy::Proxy::Vmess(vmess) => {
                let tls = if vmess.tls.unwrap_or(false) {
                    Some(TlsParams {
                        enabled: true,
                        server_name: vmess.servername.clone(),
                        insecure: vmess.skip_cert_verify,
                        alpn: None,
                    })
                } else {
                    None
                };
                let transport = vmess.network.as_ref().map(|n| {
                    let mut tp = TransportParams {
                        transport_type: n.clone(),
                        path: None,
                        host: None,
                        service_name: None,
                        headers: None,
                        max_early_data: None,
                        early_data_header_name: None,
                    };
                    if let Some(ref ws) = vmess.ws_opts {
                        tp.path = ws.path.clone();
                    }
                    if let Some(ref grpc) = vmess.grpc_opts {
                        tp.service_name = grpc.grpc_service_name.clone();
                    }
                    if let Some(ref h2) = vmess.h2_opts {
                        tp.path = h2.path.clone();
                        tp.host = h2.host.clone();
                    }
                    tp
                });
                (
                    ProxyParams::Vmess {
                        uuid: vmess.uuid.clone().unwrap_or_default(),
                        alter_id: vmess.alter_id.map(|a| a as u32),
                        security: vmess.cipher.clone(),
                        tls,
                        transport,
                    },
                    "vmess".to_string(),
                    None,
                    None,
                )
            }
            clash::proxy::Proxy::Trojan(trojan) => {
                let tls = Some(TlsParams {
                    enabled: true,
                    server_name: trojan.sni.clone(),
                    insecure: trojan.skip_cert_verify,
                    alpn: if trojan.alpn.is_empty() {
                        None
                    } else {
                        Some(trojan.alpn.clone())
                    },
                });
                let transport = trojan.network.as_ref().map(|n| {
                    let mut tp = TransportParams {
                        transport_type: n.clone(),
                        path: None,
                        host: None,
                        service_name: None,
                        headers: None,
                        max_early_data: None,
                        early_data_header_name: None,
                    };
                    if let Some(ref ws) = trojan.ws_opts {
                        tp.path = ws.path.clone();
                    }
                    if let Some(ref grpc) = trojan.grpc_opts {
                        tp.service_name = grpc.grpc_service_name.clone();
                    }
                    tp
                });
                (
                    ProxyParams::Trojan { tls, transport },
                    "trojan".to_string(),
                    trojan.password.clone(),
                    None,
                )
            }
            _ => (
                ProxyParams::Generic,
                proxy_json.get("type")?.as_str()?.to_string(),
                None,
                None,
            ),
        };

        // Normalize protocol names: clash uses "ss" but sing-box uses "shadowsocks"
        let protocol = if protocol == "ss" {
            "shadowsocks".to_string()
        } else {
            protocol
        };

        // Build the old-style parameters HashMap from JSON (backward compat)
        let name = proxy.name().to_string();
        let server = proxy_json.get("server")?.as_str()?.to_string();
        let port = proxy_json.get("port")?.as_u64()? as u16;

        let skip_keys = [
            "name", "type", "server", "port", "password", "cipher", "method",
        ];
        let mut parameters = HashMap::new();
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
            params,
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

    /// Extract TLS params from a sing-box TLS outbound config
    fn extract_singbox_tls_params(
        tls: &Option<crate::protocols::singbox::common::tls::Outbound>,
    ) -> Option<TlsParams> {
        let t = tls.as_ref()?;
        Some(TlsParams {
            enabled: t.enabled.unwrap_or(false),
            server_name: t.server_name.clone(),
            insecure: t.insecure,
            alpn: t.alpn.clone(),
        })
    }

    /// Extract transport params from a sing-box Transport enum
    fn extract_singbox_transport_params(
        transport: &Option<crate::protocols::singbox::common::transport::Transport>,
    ) -> Option<TransportParams> {
        let t = transport.as_ref()?;
        // Serialize to JSON to uniformly extract fields from Transport variants
        let json = serde_json::to_value(t).ok()?;
        let obj = json.as_object()?;
        Some(TransportParams {
            transport_type: obj.get("type")?.as_str()?.to_string(),
            path: obj
                .get("path")
                .and_then(|v| v.as_str())
                .map(String::from),
            host: obj
                .get("host")
                .and_then(|v| v.as_array())
                .map(|a| {
                    a.iter()
                        .filter_map(|v| v.as_str().map(String::from))
                        .collect()
                }),
            service_name: obj
                .get("service_name")
                .and_then(|v| v.as_str())
                .map(String::from),
            headers: None,
            max_early_data: obj
                .get("max_early_data")
                .and_then(|v| v.as_u64())
                .map(|v| v as usize),
            early_data_header_name: obj
                .get("early_data_header_name")
                .and_then(|v| v.as_str())
                .map(String::from),
        })
    }

    /// Parse a single Sing-box outbound entry (strongly typed)
    fn parse_singbox_outbound(outbound: &singbox::outbound::Outbound) -> Option<ProxyServer> {
        let outbound_json = match serde_json::to_value(outbound) {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!("Failed to serialize Sing-box outbound: {}", e);
                return None;
            }
        };

        let outbound_type = outbound_json.get("type")?.as_str()?;

        // Skip non-proxy outbound types
        let proxy_types = [
            "shadowsocks",
            "vmess",
            "vless",
            "trojan",
            "naive",
            "hysteria",
            "hysteria2",
            "shadowtls",
            "tuic",
            "anytls",
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

        // Extract typed params from the strong outbound type
        let params = match outbound {
            singbox::outbound::Outbound::Shadowsocks(ss) => ProxyParams::Shadowsocks {
                cipher: ss.method.clone(),
                udp: None,
                plugin: ss.plugin.clone(),
                plugin_opts: ss.plugin_opts.clone(),
            },
            singbox::outbound::Outbound::Vmess(vmess) => ProxyParams::Vmess {
                uuid: vmess.uuid.clone(),
                alter_id: vmess.alter_id,
                security: vmess.security.clone(),
                tls: Self::extract_singbox_tls_params(&vmess.tls),
                transport: Self::extract_singbox_transport_params(&vmess.transport),
            },
            singbox::outbound::Outbound::Trojan(t) => ProxyParams::Trojan {
                tls: Self::extract_singbox_tls_params(&t.tls),
                transport: Self::extract_singbox_transport_params(&t.transport),
            },
            singbox::outbound::Outbound::Vless(v) => ProxyParams::Vless {
                uuid: v.uuid.clone(),
                flow: v.flow.clone(),
                tls: Self::extract_singbox_tls_params(&v.tls),
                transport: Self::extract_singbox_transport_params(&v.transport),
            },
            singbox::outbound::Outbound::Hysteria2(h2) => ProxyParams::Hysteria2 {
                obfs_password: h2.obfs.as_ref().and_then(|o| {
                    // Serialize Obfs to get the password field
                    serde_json::to_value(o)
                        .ok()
                        .and_then(|v| v.get("password").and_then(|p| p.as_str()).map(String::from))
                }),
                tls: Self::extract_singbox_tls_params(&h2.tls),
            },
            _ => ProxyParams::Generic,
        };

        // Collect additional parameters (backward compat)
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
            params,
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
            params: ProxyParams::Generic,
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
