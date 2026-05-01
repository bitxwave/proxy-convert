//! Subscription and plain-text proxy list parsing.
//!
//! Parses vmess://, trojan://, ss:// (SIP002 and legacy) and multi-line content.
//! Used by ProtocolRegistry for "subscription" and "plain" formats.

use crate::core::error::Result;
use crate::protocols::detect::is_base64_encoded;
use crate::protocols::{ProxyParams, ProxyServer};
use std::collections::HashMap;

/// Parse subscription format (possibly base64-encoded, then one proxy per line).
pub fn parse_subscription(content: &str) -> Result<Vec<ProxyServer>> {
    let content = if is_base64_encoded(content) {
        let clean: String = content.chars().filter(|c| !c.is_whitespace()).collect();
        if let Ok(decoded) =
            base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &clean)
        {
            String::from_utf8(decoded).unwrap_or_else(|_| content.to_string())
        } else {
            content.to_string()
        }
    } else {
        content.to_string()
    };
    parse_plain_text(&content)
}

/// Parse plain text (one proxy URL per line; # comments and empty lines skipped).
pub fn parse_plain_text(content: &str) -> Result<Vec<ProxyServer>> {
    let mut servers = Vec::new();
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(server) = parse_proxy_url(line)? {
            servers.push(server);
        }
    }
    Ok(servers)
}

/// Parse a single proxy URL.
pub fn parse_proxy_url(url: &str) -> Result<Option<ProxyServer>> {
    if url.starts_with("vmess://") {
        parse_vmess_url(url)
    } else if url.starts_with("vless://") {
        parse_vless_url(url)
    } else if url.starts_with("trojan://") {
        parse_trojan_url(url)
    } else if url.starts_with("ss://") {
        parse_shadowsocks_url(url)
    } else if url.starts_with("hysteria2://") || url.starts_with("hy2://") {
        parse_hysteria2_url(url)
    } else {
        tracing::warn!("Unsupported proxy URL: {}", url);
        Ok(None)
    }
}

fn parse_vmess_url(url: &str) -> Result<Option<ProxyServer>> {
    let vmess_part = url.strip_prefix("vmess://").unwrap_or("");
    let at_pos = match vmess_part.find('@') {
        Some(p) => p,
        None => return Ok(None),
    };
    let uuid = &vmess_part[..at_pos];
    let rest = &vmess_part[at_pos + 1..];
    let (server_port, name) = match rest.find('#') {
        Some(hash_pos) => (&rest[..hash_pos], &rest[hash_pos + 1..]),
        None => return Ok(None),
    };
    let colon_pos = match server_port.find(':') {
        Some(p) => p,
        None => return Ok(None),
    };
    let server = &server_port[..colon_pos];
    let port = server_port[colon_pos + 1..].parse::<u16>().unwrap_or(0);
    Ok(Some(ProxyServer {
        name: name.to_string(),
        protocol: "vmess".to_string(),
        server: server.to_string(),
        port,
        password: None,
        method: None,
        params: ProxyParams::Vmess {
            uuid: uuid.to_string(),
            alter_id: None,
            security: None,
            tls: None,
            transport: None,
            extras: HashMap::new(),
        },
    }))
}

fn parse_trojan_url(url: &str) -> Result<Option<ProxyServer>> {
    let trojan_part = url.strip_prefix("trojan://").unwrap_or("");
    let at_pos = match trojan_part.find('@') {
        Some(p) => p,
        None => return Ok(None),
    };
    let password = &trojan_part[..at_pos];
    let rest = &trojan_part[at_pos + 1..];
    let (server_port, name) = match rest.find('#') {
        Some(hash_pos) => (&rest[..hash_pos], &rest[hash_pos + 1..]),
        None => return Ok(None),
    };
    let colon_pos = match server_port.find(':') {
        Some(p) => p,
        None => return Ok(None),
    };
    let server = &server_port[..colon_pos];
    let port = server_port[colon_pos + 1..].parse::<u16>().unwrap_or(0);
    Ok(Some(ProxyServer {
        name: name.to_string(),
        protocol: "trojan".to_string(),
        server: server.to_string(),
        port,
        password: Some(password.to_string()),
        method: None,
        params: ProxyParams::Trojan {
            tls: None,
            transport: None,
            extras: HashMap::new(),
        },
    }))
}

fn parse_shadowsocks_url(url: &str) -> Result<Option<ProxyServer>> {
    let ss_part = url.strip_prefix("ss://").unwrap_or("");
    let (main_part, name) = if let Some(hash_pos) = ss_part.find('#') {
        let name_encoded = &ss_part[hash_pos + 1..];
        let name = urlencoding::decode(name_encoded)
            .unwrap_or_else(|_| std::borrow::Cow::Borrowed(name_encoded))
            .to_string();
        (&ss_part[..hash_pos], name)
    } else {
        (ss_part, String::new())
    };
    let main_part = main_part.split('?').next().unwrap_or(main_part);

    if let Some(at_pos) = main_part.rfind('@') {
        let encoded = &main_part[..at_pos];
        let server_port = &main_part[at_pos + 1..];
        let (server, port) = if let Some(colon_pos) = server_port.rfind(':') {
            (
                server_port[..colon_pos].to_string(),
                server_port[colon_pos + 1..].parse::<u16>().unwrap_or(0),
            )
        } else {
            return Ok(None);
        };
        let decoded_result = base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD,
            encoded,
        )
        .or_else(|_| {
            base64::Engine::decode(&base64::engine::general_purpose::URL_SAFE, encoded)
        })
        .or_else(|_| {
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
                        params: ProxyParams::Shadowsocks {
                            cipher: method.to_string(),
                            udp: None,
                            plugin: None,
                            plugin_opts: None,
                            extras: HashMap::new(),
                        },
                    }));
                }
            }
        }
    }

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
                            params: ProxyParams::Shadowsocks {
                                cipher: method.to_string(),
                                udp: None,
                                plugin: None,
                                plugin_opts: None,
                                extras: HashMap::new(),
                            },
                        }));
                    }
                }
            }
        }
    }

    Ok(None)
}

/// Parse vless://uuid@server:port?type=...&security=...#name
fn parse_vless_url(url: &str) -> Result<Option<ProxyServer>> {
    let vless_part = url.strip_prefix("vless://").unwrap_or("");
    let at_pos = match vless_part.find('@') {
        Some(p) => p,
        None => return Ok(None),
    };
    let uuid = &vless_part[..at_pos];
    let rest = &vless_part[at_pos + 1..];

    let (server_port_query, name) = match rest.find('#') {
        Some(hash_pos) => {
            let name_encoded = &rest[hash_pos + 1..];
            let name = urlencoding::decode(name_encoded)
                .unwrap_or_else(|_| std::borrow::Cow::Borrowed(name_encoded))
                .to_string();
            (&rest[..hash_pos], name)
        }
        None => (rest, String::new()),
    };

    let (server_port, query_str) = match server_port_query.find('?') {
        Some(q) => (&server_port_query[..q], Some(&server_port_query[q + 1..])),
        None => (server_port_query, None),
    };

    let colon_pos = match server_port.rfind(':') {
        Some(p) => p,
        None => return Ok(None),
    };
    let server = &server_port[..colon_pos];
    let port = server_port[colon_pos + 1..].parse::<u16>().unwrap_or(0);

    let mut flow = None;
    let mut sni = None;
    let mut transport_type = None;
    let mut path = None;
    let mut service_name = None;

    if let Some(qs) = query_str {
        for (k, v) in url::form_urlencoded::parse(qs.as_bytes()) {
            match k.as_ref() {
                "flow" => flow = Some(v.into_owned()),
                "sni" | "peer" => sni = Some(v.into_owned()),
                "type" => transport_type = Some(v.into_owned()),
                "path" => path = Some(v.into_owned()),
                "serviceName" => service_name = Some(v.into_owned()),
                _ => {}
            }
        }
    }

    let tls = sni.as_ref().map(|s| crate::protocols::TlsParams {
        enabled: true,
        server_name: Some(s.clone()),
        insecure: None,
        alpn: None,
    });

    let transport = transport_type.as_ref().and_then(|t| {
        if t == "tcp" || t == "none" {
            return None;
        }
        Some(crate::protocols::TransportParams {
            transport_type: t.clone(),
            path,
            host: None,
            service_name,
            headers: None,
            max_early_data: None,
            early_data_header_name: None,
        })
    });

    Ok(Some(ProxyServer {
        name,
        protocol: "vless".to_string(),
        server: server.to_string(),
        port,
        password: None,
        method: None,
        params: ProxyParams::Vless {
            uuid: uuid.to_string(),
            flow,
            tls,
            transport,
            extras: HashMap::new(),
        },
    }))
}

/// Parse hysteria2://password@server:port?sni=...#name  (also hy2://)
fn parse_hysteria2_url(url: &str) -> Result<Option<ProxyServer>> {
    let hy2_part = url
        .strip_prefix("hysteria2://")
        .or_else(|| url.strip_prefix("hy2://"))
        .unwrap_or("");
    let at_pos = match hy2_part.find('@') {
        Some(p) => p,
        None => return Ok(None),
    };
    let password = &hy2_part[..at_pos];
    let rest = &hy2_part[at_pos + 1..];

    let (server_port_query, name) = match rest.find('#') {
        Some(hash_pos) => {
            let name_encoded = &rest[hash_pos + 1..];
            let name = urlencoding::decode(name_encoded)
                .unwrap_or_else(|_| std::borrow::Cow::Borrowed(name_encoded))
                .to_string();
            (&rest[..hash_pos], name)
        }
        None => (rest, String::new()),
    };

    let (server_port, query_str) = match server_port_query.find('?') {
        Some(q) => (&server_port_query[..q], Some(&server_port_query[q + 1..])),
        None => (server_port_query, None),
    };

    let colon_pos = match server_port.rfind(':') {
        Some(p) => p,
        None => return Ok(None),
    };
    let server = &server_port[..colon_pos];
    let port = server_port[colon_pos + 1..].parse::<u16>().unwrap_or(0);

    let mut sni = None;
    let mut insecure = None;
    let mut obfs_password = None;

    if let Some(qs) = query_str {
        for (k, v) in url::form_urlencoded::parse(qs.as_bytes()) {
            match k.as_ref() {
                "sni" | "peer" => sni = Some(v.into_owned()),
                "insecure" => insecure = Some(v == "1" || v == "true"),
                "obfs-password" | "obfs" => obfs_password = Some(v.into_owned()),
                _ => {}
            }
        }
    }

    let tls = Some(crate::protocols::TlsParams {
        enabled: true,
        server_name: sni,
        insecure,
        alpn: None,
    });

    Ok(Some(ProxyServer {
        name,
        protocol: "hysteria2".to_string(),
        server: server.to_string(),
        port,
        password: Some(password.to_string()),
        method: None,
        params: ProxyParams::Hysteria2 {
            obfs_password,
            tls,
            extras: HashMap::new(),
        },
    }))
}
