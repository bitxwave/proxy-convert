//! Subscription and plain-text proxy list parsing.
//!
//! Parses vmess://, trojan://, ss:// (SIP002 and legacy) and multi-line content.
//! Used by ProtocolRegistry for "subscription" and "plain" formats.

use crate::core::error::Result;
use crate::protocols::detect::is_base64_encoded;
use crate::protocols::ProxyServer;
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

/// Parse a single proxy URL (vmess://, trojan://, ss://).
pub fn parse_proxy_url(url: &str) -> Result<Option<ProxyServer>> {
    if url.starts_with("vmess://") {
        parse_vmess_url(url)
    } else if url.starts_with("trojan://") {
        parse_trojan_url(url)
    } else if url.starts_with("ss://") {
        parse_shadowsocks_url(url)
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
    let mut parameters = HashMap::new();
    parameters.insert("uuid".to_string(), serde_json::Value::String(uuid.to_string()));
    Ok(Some(ProxyServer {
        name: name.to_string(),
        protocol: "vmess".to_string(),
        server: server.to_string(),
        port,
        password: None,
        method: None,
        parameters,
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
                        parameters: HashMap::new(),
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
                            parameters: HashMap::new(),
                        }));
                    }
                }
            }
        }
    }

    Ok(None)
}
