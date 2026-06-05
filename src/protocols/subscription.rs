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
    } else if url.starts_with("anytls://") {
        parse_anytls_url(url)
    } else if url.starts_with("hysteria://") {
        parse_hysteria_url(url)
    } else if url.starts_with("tuic://") {
        parse_tuic_url(url)
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
    let mut security = None;
    let mut public_key = None;
    let mut short_id = None;
    let mut fingerprint = None;
    let mut alpn: Option<Vec<String>> = None;
    let mut insecure = None;

    if let Some(qs) = query_str {
        for (k, v) in url::form_urlencoded::parse(qs.as_bytes()) {
            match k.as_ref() {
                "flow" => flow = Some(v.into_owned()),
                "sni" | "peer" => sni = Some(v.into_owned()),
                "type" => transport_type = Some(v.into_owned()),
                "path" => path = Some(v.into_owned()),
                "serviceName" => service_name = Some(v.into_owned()),
                "security" => security = Some(v.into_owned()),
                "pbk" | "public-key" => public_key = Some(v.into_owned()),
                "sid" | "short-id" => short_id = Some(v.into_owned()),
                "fp" | "fingerprint" => fingerprint = Some(v.into_owned()),
                "alpn" => {
                    alpn = Some(v.split(',').map(|s| s.trim().to_string()).collect());
                }
                "allowInsecure" | "insecure" => insecure = Some(v == "1" || v == "true"),
                _ => {}
            }
        }
    }

    // VLESS implies TLS when security=tls/reality OR sni is set OR reality params present.
    let tls_enabled = security.as_deref() == Some("tls")
        || security.as_deref() == Some("reality")
        || sni.is_some()
        || public_key.is_some();
    let tls = if tls_enabled {
        Some(crate::protocols::TlsParams {
            enabled: true,
            server_name: sni,
            insecure,
            alpn,
        })
    } else {
        None
    };

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

    // Surface reality / fingerprint via extras so the Clash emitter can rebuild
    // reality-opts and client-fingerprint without losing them.
    let mut extras = HashMap::new();
    if let (Some(pk), _) = (public_key.as_ref(), short_id.as_ref()) {
        let mut reality_opts = serde_json::Map::new();
        reality_opts.insert(
            "public-key".to_string(),
            serde_json::Value::String(pk.clone()),
        );
        if let Some(sid) = short_id.as_ref() {
            reality_opts.insert(
                "short-id".to_string(),
                serde_json::Value::String(sid.clone()),
            );
        }
        extras.insert(
            "reality-opts".to_string(),
            serde_json::Value::Object(reality_opts),
        );
    }
    if let Some(fp) = fingerprint {
        extras.insert(
            "client-fingerprint".to_string(),
            serde_json::Value::String(fp),
        );
    }

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
            extras,
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
    let mut obfs = None;
    let mut obfs_password = None;
    let mut alpn: Option<Vec<String>> = None;

    if let Some(qs) = query_str {
        for (k, v) in url::form_urlencoded::parse(qs.as_bytes()) {
            match k.as_ref() {
                "sni" | "peer" => sni = Some(v.into_owned()),
                "insecure" => insecure = Some(v == "1" || v == "true"),
                "obfs" => obfs = Some(v.into_owned()),
                "obfs-password" => obfs_password = Some(v.into_owned()),
                "alpn" => {
                    alpn = Some(v.split(',').map(|s| s.trim().to_string()).collect());
                }
                _ => {}
            }
        }
    }

    let tls = Some(crate::protocols::TlsParams {
        enabled: true,
        server_name: sni,
        insecure,
        alpn,
    });

    Ok(Some(ProxyServer {
        name,
        protocol: "hysteria2".to_string(),
        server: server.to_string(),
        port,
        password: Some(password.to_string()),
        method: None,
        params: ProxyParams::Hysteria2 {
            obfs,
            obfs_password,
            up_mbps: None,
            down_mbps: None,
            tls,
            extras: HashMap::new(),
        },
    }))
}

/// Parse `anytls://password@host[:port]/?sni=...&insecure=0|1#name`.
/// Per https://github.com/anytls/anytls-go/blob/main/docs/uri_scheme.md the
/// port defaults to 443 when omitted.
fn parse_anytls_url(url: &str) -> Result<Option<ProxyServer>> {
    let body = url.strip_prefix("anytls://").unwrap_or("");

    // Split off the fragment (#name) first; it's allowed to contain anything.
    let (head, name) = match body.find('#') {
        Some(pos) => {
            let raw = &body[pos + 1..];
            let decoded = urlencoding::decode(raw)
                .unwrap_or_else(|_| std::borrow::Cow::Borrowed(raw))
                .to_string();
            (&body[..pos], decoded)
        }
        None => (body, String::new()),
    };

    // Userinfo (password) → host[:port] → optional path/query
    let at_pos = match head.find('@') {
        Some(p) => p,
        None => return Ok(None),
    };
    let password_raw = &head[..at_pos];
    let password = urlencoding::decode(password_raw)
        .unwrap_or_else(|_| std::borrow::Cow::Borrowed(password_raw))
        .to_string();
    let after_auth = &head[at_pos + 1..];

    // Strip optional "/" between authority and "?...". The scheme accepts both
    // "anytls://pw@host:port?x=1" and "anytls://pw@host:port/?x=1".
    let (authority, query_str) = match after_auth.find('?') {
        Some(q) => {
            let auth_raw = &after_auth[..q];
            let auth = auth_raw.strip_suffix('/').unwrap_or(auth_raw);
            (auth, Some(&after_auth[q + 1..]))
        }
        None => {
            let auth = after_auth.strip_suffix('/').unwrap_or(after_auth);
            (auth, None)
        }
    };

    // host[:port] — handle IPv6 in brackets.
    let (server, port) = if let Some(stripped) = authority.strip_prefix('[') {
        // [v6]:port or [v6]
        let close = match stripped.find(']') {
            Some(p) => p,
            None => return Ok(None),
        };
        let host = &stripped[..close];
        let after = &stripped[close + 1..];
        let port = if let Some(rest) = after.strip_prefix(':') {
            rest.parse::<u16>().unwrap_or(443)
        } else {
            443
        };
        (host.to_string(), port)
    } else if let Some(colon) = authority.rfind(':') {
        let host = &authority[..colon];
        let port = authority[colon + 1..].parse::<u16>().unwrap_or(443);
        (host.to_string(), port)
    } else {
        (authority.to_string(), 443u16)
    };

    let mut sni = None;
    let mut insecure = None;
    if let Some(qs) = query_str {
        for (k, v) in url::form_urlencoded::parse(qs.as_bytes()) {
            match k.as_ref() {
                "sni" | "peer" => sni = Some(v.into_owned()),
                "insecure" | "allowInsecure" => {
                    insecure = Some(v == "1" || v == "true");
                }
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
        protocol: "anytls".to_string(),
        server,
        port,
        password: Some(password),
        method: None,
        params: ProxyParams::AnyTls {
            tls,
            idle_session_check_interval: None,
            idle_session_timeout: None,
            min_idle_session: None,
            extras: HashMap::new(),
        },
    }))
}

/// Split `host[:port]` (with optional IPv6 brackets) into `(host, port)`.
/// Falls back to `default_port` when no port is present.
fn split_authority(authority: &str, default_port: u16) -> Option<(String, u16)> {
    if let Some(stripped) = authority.strip_prefix('[') {
        let close = stripped.find(']')?;
        let host = &stripped[..close];
        let after = &stripped[close + 1..];
        let port = if let Some(rest) = after.strip_prefix(':') {
            rest.parse::<u16>().unwrap_or(default_port)
        } else {
            default_port
        };
        Some((host.to_string(), port))
    } else if let Some(colon) = authority.rfind(':') {
        let host = &authority[..colon];
        let port = authority[colon + 1..].parse::<u16>().unwrap_or(default_port);
        Some((host.to_string(), port))
    } else {
        Some((authority.to_string(), default_port))
    }
}

/// Parse `hysteria://host:port?auth=&peer=&insecure=&upmbps=&downmbps=&obfs=#name`.
/// (Hysteria v1 share-link format, used by some clients.)
fn parse_hysteria_url(url: &str) -> Result<Option<ProxyServer>> {
    let body = url.strip_prefix("hysteria://").unwrap_or("");

    let (head, name) = match body.find('#') {
        Some(p) => {
            let raw = &body[p + 1..];
            let n = urlencoding::decode(raw)
                .unwrap_or_else(|_| std::borrow::Cow::Borrowed(raw))
                .to_string();
            (&body[..p], n)
        }
        None => (body, String::new()),
    };

    let (authority, query_str) = match head.find('?') {
        Some(q) => (head[..q].trim_end_matches('/'), Some(&head[q + 1..])),
        None => (head.trim_end_matches('/'), None),
    };

    let (server, port) = match split_authority(authority, 443) {
        Some(s) => s,
        None => return Ok(None),
    };

    let mut auth = None;
    let mut sni = None;
    let mut insecure = None;
    let mut up_mbps = None;
    let mut down_mbps = None;
    let mut obfs = None;
    let mut alpn: Option<Vec<String>> = None;

    if let Some(qs) = query_str {
        for (k, v) in url::form_urlencoded::parse(qs.as_bytes()) {
            match k.as_ref() {
                "auth" | "auth_str" | "auth-str" => auth = Some(v.into_owned()),
                "peer" | "sni" => sni = Some(v.into_owned()),
                "insecure" => insecure = Some(v == "1" || v == "true"),
                "upmbps" | "up_mbps" => up_mbps = v.parse::<u32>().ok(),
                "downmbps" | "down_mbps" => down_mbps = v.parse::<u32>().ok(),
                "obfs" => obfs = Some(v.into_owned()),
                "alpn" => alpn = Some(v.split(',').map(|s| s.trim().to_string()).collect()),
                _ => {}
            }
        }
    }

    let tls = Some(crate::protocols::TlsParams {
        enabled: true,
        server_name: sni,
        insecure,
        alpn,
    });

    Ok(Some(ProxyServer {
        name,
        protocol: "hysteria".to_string(),
        server,
        port,
        password: auth.clone(),
        method: None,
        params: ProxyParams::Hysteria {
            auth_str: auth,
            obfs,
            up_mbps,
            down_mbps,
            tls,
            extras: HashMap::new(),
        },
    }))
}

/// Parse `tuic://uuid:password@host:port?sni=&alpn=&allow_insecure=&congestion_control=&udp_relay_mode=#name`.
/// (TUIC v5 share-link format. v4-style `tuic://token@...` is not supported here.)
fn parse_tuic_url(url: &str) -> Result<Option<ProxyServer>> {
    let body = url.strip_prefix("tuic://").unwrap_or("");

    let (head, name) = match body.find('#') {
        Some(p) => {
            let raw = &body[p + 1..];
            let n = urlencoding::decode(raw)
                .unwrap_or_else(|_| std::borrow::Cow::Borrowed(raw))
                .to_string();
            (&body[..p], n)
        }
        None => (body, String::new()),
    };

    let at_pos = match head.find('@') {
        Some(p) => p,
        None => return Ok(None),
    };
    let userinfo = &head[..at_pos];
    let after_auth = &head[at_pos + 1..];

    let (uuid, password) = match userinfo.find(':') {
        Some(c) => {
            let u = urlencoding::decode(&userinfo[..c])
                .unwrap_or_else(|_| std::borrow::Cow::Borrowed(&userinfo[..c]))
                .to_string();
            let p = urlencoding::decode(&userinfo[c + 1..])
                .unwrap_or_else(|_| std::borrow::Cow::Borrowed(&userinfo[c + 1..]))
                .to_string();
            (Some(u), Some(p))
        }
        None => (
            Some(
                urlencoding::decode(userinfo)
                    .unwrap_or_else(|_| std::borrow::Cow::Borrowed(userinfo))
                    .to_string(),
            ),
            None,
        ),
    };

    let (authority, query_str) = match after_auth.find('?') {
        Some(q) => (after_auth[..q].trim_end_matches('/'), Some(&after_auth[q + 1..])),
        None => (after_auth.trim_end_matches('/'), None),
    };

    let (server, port) = match split_authority(authority, 443) {
        Some(s) => s,
        None => return Ok(None),
    };

    let mut sni = None;
    let mut insecure = None;
    let mut alpn: Option<Vec<String>> = None;
    let mut congestion_control = None;
    let mut udp_relay_mode = None;
    let mut zero_rtt = None;

    if let Some(qs) = query_str {
        for (k, v) in url::form_urlencoded::parse(qs.as_bytes()) {
            match k.as_ref() {
                "sni" | "peer" => sni = Some(v.into_owned()),
                "allow_insecure" | "insecure" => insecure = Some(v == "1" || v == "true"),
                "alpn" => alpn = Some(v.split(',').map(|s| s.trim().to_string()).collect()),
                "congestion_control" | "congestion-control" | "congestion-controller" => {
                    congestion_control = Some(v.into_owned())
                }
                "udp_relay_mode" | "udp-relay-mode" => udp_relay_mode = Some(v.into_owned()),
                "reduce_rtt" | "zero_rtt_handshake" | "0rtt" => {
                    zero_rtt = Some(v == "1" || v == "true")
                }
                _ => {}
            }
        }
    }

    let tls = Some(crate::protocols::TlsParams {
        enabled: true,
        server_name: sni,
        insecure,
        alpn,
    });

    Ok(Some(ProxyServer {
        name,
        protocol: "tuic".to_string(),
        server,
        port,
        password,
        method: None,
        params: ProxyParams::Tuic {
            uuid,
            token: None,
            congestion_control,
            udp_relay_mode,
            zero_rtt_handshake: zero_rtt,
            heartbeat: None,
            tls,
            extras: HashMap::new(),
        },
    }))
}
