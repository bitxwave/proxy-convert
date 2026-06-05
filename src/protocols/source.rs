//! Parsed source model: typed `Config` variants per protocol and
//! the cross-protocol `ProxyServer` extraction logic.
//!
//! Lives under `protocols` because its variants wrap protocol-specific
//! configs — keeping it here avoids a backwards `utils -> protocols` edge.

use super::{clash, singbox, v2ray, ProxyParams, ProxyServer, TlsParams, TransportParams};
use crate::core::error::Result;
use crate::core::source::SourceMeta;
use std::collections::HashMap;

/// Parse a Hysteria-style bandwidth value to mbps.
/// Accepts `"30 Mbps"`, `"30Mbps"`, `30`, `"100"` etc. Returns None if unparseable.
fn parse_bandwidth_mbps_value(v: &serde_json::Value) -> Option<u32> {
    if let Some(n) = v.as_u64() {
        return Some(n as u32);
    }
    if let Some(s) = v.as_str() {
        // Strip unit; tolerate "30 Mbps" / "30mbps" / "30M" / "30".
        let digits: String = s.chars().take_while(|c| c.is_ascii_digit()).collect();
        if !digits.is_empty() {
            return digits.parse::<u32>().ok();
        }
    }
    None
}

/// Same as [`parse_bandwidth_mbps_value`] but takes a typed JSON Value
/// directly (used by Hysteria v1 which stores `up`/`down` as Value).
fn parse_bandwidth_mbps(v: &serde_json::Value) -> Option<u32> {
    parse_bandwidth_mbps_value(v)
}

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

        // Build per-variant `extras` from the JSON dump minus fields already
        // covered by ProxyServer's typed top-level fields.
        let skip_keys: &[&str] = &[
            "name", "type", "server", "port", "password", "cipher", "method",
        ];
        let mut extras_map: HashMap<String, serde_json::Value> = HashMap::new();
        if let Some(obj) = proxy_json.as_object() {
            for (key, value) in obj {
                if !skip_keys.contains(&key.as_str()) {
                    extras_map.insert(key.clone(), value.clone());
                }
            }
        }

        // Extract typed params directly from the strong type
        let (params, protocol, password, method) = match proxy {
            clash::proxy::Proxy::Ss(ss) => (
                ProxyParams::Shadowsocks {
                    cipher: ss.cipher.clone(),
                    udp: ss.udp,
                    plugin: None,
                    plugin_opts: None,
                    extras: extras_map,
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
                        extras: extras_map,
                    },
                    "vmess".to_string(),
                    None,
                    None,
                )
            }
            clash::proxy::Proxy::Anytls(at) => {
                // mihomo's anytls is always TLS. Build TlsParams from flat fields.
                let tls = Some(TlsParams {
                    enabled: true,
                    server_name: at.sni.clone(),
                    insecure: at.skip_cert_verify,
                    alpn: if at.alpn.is_empty() {
                        None
                    } else {
                        Some(at.alpn.clone())
                    },
                });
                (
                    ProxyParams::AnyTls {
                        tls,
                        idle_session_check_interval: at.idle_session_check_interval.clone(),
                        idle_session_timeout: at.idle_session_timeout.clone(),
                        min_idle_session: at.min_idle_session,
                        extras: extras_map,
                    },
                    "anytls".to_string(),
                    Some(at.password.clone()),
                    None,
                )
            }
            clash::proxy::Proxy::Vless(vless) => {
                let tls = if vless.tls.unwrap_or(false) || vless.reality_opts.is_some() {
                    Some(TlsParams {
                        enabled: true,
                        server_name: vless.servername.clone(),
                        insecure: vless.skip_cert_verify,
                        alpn: if vless.alpn.is_empty() {
                            None
                        } else {
                            Some(vless.alpn.clone())
                        },
                    })
                } else {
                    None
                };
                let transport = vless.network.as_ref().and_then(|n| {
                    if n == "tcp" || n == "none" {
                        return None;
                    }
                    let mut tp = TransportParams {
                        transport_type: n.clone(),
                        path: None,
                        host: None,
                        service_name: None,
                        headers: None,
                        max_early_data: None,
                        early_data_header_name: None,
                    };
                    if let Some(ref ws) = vless.ws_opts {
                        tp.path = ws.path.clone();
                    }
                    if let Some(ref grpc) = vless.grpc_opts {
                        tp.service_name = grpc.grpc_service_name.clone();
                    }
                    if let Some(ref h2) = vless.h2_opts {
                        tp.path = h2.path.clone();
                        tp.host = h2.host.clone();
                    }
                    Some(tp)
                });
                (
                    ProxyParams::Vless {
                        uuid: vless.uuid.clone(),
                        flow: vless.flow.clone(),
                        tls,
                        transport,
                        extras: extras_map,
                    },
                    "vless".to_string(),
                    None,
                    None,
                )
            }
            clash::proxy::Proxy::Hysteria(h) => {
                let tls = Some(TlsParams {
                    enabled: true,
                    server_name: h.sni.clone(),
                    insecure: h.skip_cert_verify,
                    alpn: if h.alpn.is_empty() {
                        None
                    } else {
                        Some(h.alpn.clone())
                    },
                });
                let up_mbps = parse_bandwidth_mbps(&h.up);
                let down_mbps = parse_bandwidth_mbps(&h.down);
                (
                    ProxyParams::Hysteria {
                        auth_str: h.auth_str.clone(),
                        obfs: h.obfs.clone(),
                        up_mbps,
                        down_mbps,
                        tls,
                        extras: extras_map,
                    },
                    "hysteria".to_string(),
                    h.auth_str.clone(),
                    None,
                )
            }
            clash::proxy::Proxy::Hysteria2(h2) => {
                let tls = Some(TlsParams {
                    enabled: true,
                    server_name: h2.sni.clone(),
                    insecure: h2.skip_cert_verify,
                    alpn: if h2.alpn.is_empty() {
                        None
                    } else {
                        Some(h2.alpn.clone())
                    },
                });
                let up_mbps = h2.up.as_ref().and_then(parse_bandwidth_mbps_value);
                let down_mbps = h2.down.as_ref().and_then(parse_bandwidth_mbps_value);
                (
                    ProxyParams::Hysteria2 {
                        obfs: h2.obfs.clone(),
                        obfs_password: h2.obfs_password.clone(),
                        up_mbps,
                        down_mbps,
                        tls,
                        extras: extras_map,
                    },
                    "hysteria2".to_string(),
                    Some(h2.password.clone()),
                    None,
                )
            }
            clash::proxy::Proxy::Tuic(t) => {
                let tls = Some(TlsParams {
                    enabled: true,
                    server_name: t.sni.clone(),
                    insecure: t.skip_cert_verify,
                    alpn: if t.alpn.is_empty() {
                        None
                    } else {
                        Some(t.alpn.clone())
                    },
                });
                let heartbeat = t.heartbeat_interval.map(|ms| format!("{}ms", ms));
                (
                    ProxyParams::Tuic {
                        uuid: t.uuid.clone(),
                        token: t.token.clone(),
                        congestion_control: t.congestion_controller.clone(),
                        udp_relay_mode: t.udp_relay_mode.clone(),
                        zero_rtt_handshake: t.reduce_rtt,
                        heartbeat,
                        tls,
                        extras: extras_map,
                    },
                    "tuic".to_string(),
                    t.password.clone(),
                    None,
                )
            }
            clash::proxy::Proxy::Wireguard(wg) => {
                // Normalize simplified vs full peers form to a single peers list.
                let peers: Vec<crate::protocols::WireGuardPeerParams> = if let Some(ps) = &wg.peers {
                    ps.iter()
                        .map(|p| crate::protocols::WireGuardPeerParams {
                            server: p.server.clone(),
                            server_port: p.port,
                            public_key: p.public_key.clone(),
                            pre_shared_key: p.pre_shared_key.clone(),
                            allowed_ips: if p.allowed_ips.is_empty() {
                                vec!["0.0.0.0/0".to_string()]
                            } else {
                                p.allowed_ips.clone()
                            },
                            reserved: p.reserved.clone(),
                            persistent_keepalive: p.persistent_keepalive,
                        })
                        .collect()
                } else if let (Some(server), Some(port), Some(public_key)) =
                    (&wg.server, wg.port, &wg.public_key)
                {
                    vec![crate::protocols::WireGuardPeerParams {
                        server: server.clone(),
                        server_port: port,
                        public_key: public_key.clone(),
                        pre_shared_key: wg.pre_shared_key.clone(),
                        allowed_ips: if wg.allowed_ips.is_empty() {
                            vec!["0.0.0.0/0".to_string()]
                        } else {
                            wg.allowed_ips.clone()
                        },
                        reserved: wg.reserved.clone(),
                        persistent_keepalive: wg.persistent_keepalive,
                    }]
                } else {
                    Vec::new()
                };
                // Local addresses: combine ipv4 + ipv6 with /32 / /128 masks.
                let mut local_addresses = Vec::new();
                if let Some(ip) = &wg.ip {
                    local_addresses.push(format!("{}/32", ip));
                }
                if let Some(ipv6) = &wg.ipv6 {
                    local_addresses.push(format!("{}/128", ipv6));
                }
                (
                    ProxyParams::WireGuard {
                        private_key: wg.private_key.clone(),
                        local_addresses,
                        mtu: wg.mtu,
                        peers,
                        extras: extras_map,
                    },
                    "wireguard".to_string(),
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
                    ProxyParams::Trojan { tls, transport, extras: extras_map },
                    "trojan".to_string(),
                    trojan.password.clone(),
                    None,
                )
            }
            clash::proxy::Proxy::Ssr(ssr) => (
                ProxyParams::ShadowsocksR {
                    cipher: ssr.cipher.clone(),
                    protocol: ssr.protocol.clone().unwrap_or_default(),
                    obfs: ssr.obfs.clone().unwrap_or_default(),
                    obfs_param: ssr.obfs_param.clone(),
                    protocol_param: ssr.protocol_param.clone(),
                    udp: ssr.udp,
                    extras: extras_map,
                },
                "ssr".to_string(),
                Some(ssr.password.clone()),
                Some(ssr.cipher.clone()),
            ),
            clash::proxy::Proxy::Socks5(s) => {
                let tls = if s.tls.unwrap_or(false) {
                    Some(TlsParams {
                        enabled: true,
                        server_name: None,
                        insecure: s.skip_cert_verify,
                        alpn: None,
                    })
                } else {
                    None
                };
                (
                    ProxyParams::Socks {
                        version: Some("5".to_string()),
                        username: s.username.clone(),
                        tls,
                        udp: s.udp,
                        extras: extras_map,
                    },
                    "socks5".to_string(),
                    s.password.clone(),
                    None,
                )
            }
            clash::proxy::Proxy::Http(h) => (
                ProxyParams::Http {
                    username: h.username.clone(),
                    // mihomo's plain http proxy has no TLS toggle in this struct;
                    // https variants come through as `type: http` + a separate
                    // `tls: true` field passed via extras.
                    tls: None,
                    extras: extras_map,
                },
                "http".to_string(),
                h.password.clone(),
                None,
            ),
            clash::proxy::Proxy::Snell(s) => {
                let obfs_opts = s
                    .obfs_opts
                    .as_ref()
                    .and_then(|o| serde_json::to_value(o).ok());
                (
                    ProxyParams::Snell {
                        psk: s.psk.clone().unwrap_or_default(),
                        version: s.version.map(|v| v as u32),
                        obfs_opts,
                        extras: extras_map,
                    },
                    "snell".to_string(),
                    s.psk.clone(),
                    None,
                )
            }
        };

        // Normalize protocol names: clash uses "ss" but sing-box uses "shadowsocks"
        let protocol = if protocol == "ss" {
            "shadowsocks".to_string()
        } else {
            protocol
        };

        let name = proxy.name().to_string();
        // WireGuard's top-level server/port are optional (full peers form can put
        // them inside `peers[]`). Fall back to the first peer's server/port for
        // such configs, then to empty / 0 if neither is present.
        let (server, port) = if let clash::proxy::Proxy::Wireguard(wg) = proxy {
            let s = wg
                .server
                .clone()
                .or_else(|| wg.peers.as_ref().and_then(|ps| ps.first().map(|p| p.server.clone())))
                .unwrap_or_default();
            let p = wg
                .port
                .or_else(|| wg.peers.as_ref().and_then(|ps| ps.first().map(|p| p.port)))
                .unwrap_or(0);
            (s, p)
        } else {
            let s = proxy_json.get("server")?.as_str()?.to_string();
            let p = proxy_json.get("port")?.as_u64()? as u16;
            (s, p)
        };

        Some(ProxyServer {
            name,
            protocol,
            server,
            port,
            password,
            method,
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

        // Leftover JSON fields, mapped to the variant's `extras`.
        let skip_keys: &[&str] = &[
            "type", "tag", "server", "server_port", "port", "password", "method",
        ];
        let mut extras_map: HashMap<String, serde_json::Value> = HashMap::new();
        if let Some(obj) = outbound_json.as_object() {
            for (key, value) in obj {
                if !skip_keys.contains(&key.as_str()) {
                    extras_map.insert(key.clone(), value.clone());
                }
            }
        }

        let params = match outbound {
            singbox::outbound::Outbound::Shadowsocks(ss) => ProxyParams::Shadowsocks {
                cipher: ss.method.clone(),
                udp: None,
                plugin: ss.plugin.clone(),
                plugin_opts: ss.plugin_opts.clone(),
                extras: extras_map,
            },
            singbox::outbound::Outbound::Vmess(vmess) => ProxyParams::Vmess {
                uuid: vmess.uuid.clone(),
                alter_id: vmess.alter_id,
                security: vmess.security.clone(),
                tls: Self::extract_singbox_tls_params(&vmess.tls),
                transport: Self::extract_singbox_transport_params(&vmess.transport),
                extras: extras_map,
            },
            singbox::outbound::Outbound::Trojan(t) => ProxyParams::Trojan {
                tls: Self::extract_singbox_tls_params(&t.tls),
                transport: Self::extract_singbox_transport_params(&t.transport),
                extras: extras_map,
            },
            singbox::outbound::Outbound::Vless(v) => ProxyParams::Vless {
                uuid: v.uuid.clone(),
                flow: v.flow.clone(),
                tls: Self::extract_singbox_tls_params(&v.tls),
                transport: Self::extract_singbox_transport_params(&v.transport),
                extras: extras_map,
            },
            singbox::outbound::Outbound::Hysteria2(h2) => {
                let obfs_value = h2.obfs.as_ref().and_then(|o| serde_json::to_value(o).ok());
                let obfs_type = obfs_value
                    .as_ref()
                    .and_then(|v| v.get("type").and_then(|t| t.as_str()).map(String::from));
                let obfs_password = obfs_value
                    .as_ref()
                    .and_then(|v| v.get("password").and_then(|p| p.as_str()).map(String::from));
                ProxyParams::Hysteria2 {
                    obfs: obfs_type,
                    obfs_password,
                    up_mbps: h2.up_mbps,
                    down_mbps: h2.down_mbps,
                    tls: Self::extract_singbox_tls_params(&h2.tls),
                    extras: extras_map,
                }
            }
            singbox::outbound::Outbound::Hysteria(h) => ProxyParams::Hysteria {
                auth_str: h.auth_str.clone().or_else(|| h.auth.clone()),
                obfs: h.obfs.clone(),
                up_mbps: Some(h.up_mbps),
                down_mbps: Some(h.down_mbps),
                tls: Self::extract_singbox_tls_params(&h.tls),
                extras: extras_map,
            },
            singbox::outbound::Outbound::Tuic(t) => ProxyParams::Tuic {
                uuid: Some(t.uuid.clone()),
                token: None,
                congestion_control: t
                    .congestion_control
                    .as_ref()
                    .and_then(|c| serde_json::to_value(c).ok())
                    .and_then(|v| v.as_str().map(String::from)),
                udp_relay_mode: t
                    .udp_relay_mode
                    .as_ref()
                    .and_then(|c| serde_json::to_value(c).ok())
                    .and_then(|v| v.as_str().map(String::from)),
                zero_rtt_handshake: t.zero_rtt_handshake,
                heartbeat: t.heartbeat.clone(),
                tls: Self::extract_singbox_tls_params(&t.tls),
                extras: extras_map,
            },
            singbox::outbound::Outbound::Wireguard(wg) => {
                let peers = match &wg.peers {
                    Some(ps) => ps
                        .iter()
                        .map(|p| crate::protocols::WireGuardPeerParams {
                            server: p.server.clone().unwrap_or_default(),
                            server_port: p.server_port.unwrap_or(0),
                            public_key: p.public_key.clone().unwrap_or_default(),
                            pre_shared_key: p.pre_shared_key.clone(),
                            allowed_ips: p
                                .allowed_ips
                                .clone()
                                .unwrap_or_else(|| vec!["0.0.0.0/0".to_string()]),
                            reserved: p.reserved.as_ref().map(|r| {
                                serde_json::Value::Array(
                                    r.iter()
                                        .map(|n| serde_json::Value::Number((*n).into()))
                                        .collect(),
                                )
                            }),
                            persistent_keepalive: None,
                        })
                        .collect(),
                    None => Vec::new(),
                };
                ProxyParams::WireGuard {
                    private_key: wg.private_key.clone().unwrap_or_default(),
                    local_addresses: wg.local_address.clone().unwrap_or_default(),
                    mtu: wg.mtu.map(|m| m as u32),
                    peers,
                    extras: extras_map,
                }
            }
            singbox::outbound::Outbound::Anytls(at) => ProxyParams::AnyTls {
                tls: Self::extract_singbox_tls_params(&Some(at.tls.clone())),
                idle_session_check_interval: at
                    .idle_session_check_interval
                    .clone()
                    .map(serde_json::Value::String),
                idle_session_timeout: at
                    .idle_session_timeout
                    .clone()
                    .map(serde_json::Value::String),
                min_idle_session: at.min_idle_session,
                extras: extras_map,
            },
            _ => ProxyParams::Generic { extras: extras_map },
        };

        Some(ProxyServer {
            name: tag,
            protocol: outbound_type.to_string(),
            server,
            port,
            password,
            method,
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

        // V2Ray source isn't fully typed yet — route the extras through
        // ProxyParams::Generic so processors that need pass-through can read them.
        let extras = outbound.extra.clone().into_iter().collect();

        Some(ProxyServer {
            name: tag,
            protocol: protocol.to_string(),
            server,
            port,
            password,
            method,
            params: ProxyParams::Generic { extras },
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
