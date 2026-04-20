//! Shared transport/TLS conversion logic between Clash and sing-box formats.
//!
//! Provides functions to convert TLS and transport parameters bidirectionally:
//! - Clash-style flat params <-> sing-box nested objects

use std::collections::HashMap;
use serde_json::{Map, Value};

/// Convert Clash-style TLS params to sing-box TLS object.
/// Handles both cases:
/// - params["tls"] is already a sing-box style object -> pass through (ensure "enabled" key exists)
/// - params has flat Clash-style keys (sni, servername, skip-cert-verify, alpn) -> build new object
/// For trojan, always_enabled=true (trojan implies TLS).
pub fn clash_tls_to_singbox(
    params: &HashMap<String, Value>,
    always_enabled: bool,
) -> Option<Value> {
    // If params["tls"] is already an object, pass through
    if let Some(tls) = params.get("tls") {
        if let Some(tls_obj) = tls.as_object() {
            let mut result = tls_obj.clone();
            result.entry("enabled".to_string()).or_insert(Value::Bool(true));
            return Some(Value::Object(result));
        }
        // tls is a boolean
        if !always_enabled && !tls.as_bool().unwrap_or(false) {
            return None;
        }
    } else if !always_enabled {
        return None;
    }

    // Build from flat params
    let mut tls_config = Map::new();
    tls_config.insert("enabled".to_string(), Value::Bool(true));
    if let Some(sni) = params.get("sni").or(params.get("servername")) {
        tls_config.insert("server_name".to_string(), sni.clone());
    }
    if let Some(skip) = params.get("skip-cert-verify") {
        tls_config.insert("insecure".to_string(), skip.clone());
    }
    if let Some(alpn) = params.get("alpn") {
        tls_config.insert("alpn".to_string(), alpn.clone());
    }
    Some(Value::Object(tls_config))
}

/// Convert Clash-style transport params (network + *-opts) to sing-box transport object.
/// Handles both cases:
/// - params["transport"] is already a sing-box style object -> pass through
/// - params has Clash-style "network" key with *-opts -> build new object
pub fn clash_transport_to_singbox(
    params: &HashMap<String, Value>,
) -> Option<Value> {
    // If already a singbox transport object, pass through
    if let Some(transport) = params.get("transport") {
        if transport.is_object() {
            return Some(transport.clone());
        }
    }

    let network = params.get("network")?.as_str()?;
    let mut transport = Map::new();
    transport.insert("type".to_string(), Value::String(network.to_string()));

    match network {
        "ws" => {
            if let Some(ws_opts) = params.get("ws-opts") {
                if let Some(path) = ws_opts.get("path") { transport.insert("path".to_string(), path.clone()); }
                if let Some(headers) = ws_opts.get("headers") { transport.insert("headers".to_string(), headers.clone()); }
                if let Some(ed) = ws_opts.get("max-early-data") { transport.insert("max_early_data".to_string(), ed.clone()); }
                if let Some(edn) = ws_opts.get("early-data-header-name") { transport.insert("early_data_header_name".to_string(), edn.clone()); }
            }
        }
        "grpc" => {
            if let Some(grpc_opts) = params.get("grpc-opts") {
                if let Some(sn) = grpc_opts.get("grpc-service-name") { transport.insert("service_name".to_string(), sn.clone()); }
            }
        }
        "h2" => {
            if let Some(h2_opts) = params.get("h2-opts") {
                if let Some(host) = h2_opts.get("host") { transport.insert("host".to_string(), host.clone()); }
                if let Some(path) = h2_opts.get("path") { transport.insert("path".to_string(), path.clone()); }
            }
        }
        "http" => {
            if let Some(http_opts) = params.get("http-opts") {
                if let Some(method) = http_opts.get("method") { transport.insert("method".to_string(), method.clone()); }
                if let Some(path) = http_opts.get("path") { transport.insert("path".to_string(), path.clone()); }
                if let Some(headers) = http_opts.get("headers") { transport.insert("headers".to_string(), headers.clone()); }
            }
        }
        _ => {}
    }

    if transport.len() > 1 { Some(Value::Object(transport)) } else { None }
}

/// Convert sing-box TLS object to Clash-style TLS params on config map.
pub fn singbox_tls_to_clash(
    config: &mut Map<String, Value>,
    tls: &Value,
) {
    if let Some(tls_obj) = tls.as_object() {
        if let Some(server_name) = tls_obj.get("server_name") {
            config.insert("sni".to_string(), server_name.clone());
        }
        if let Some(insecure) = tls_obj.get("insecure") {
            config.insert("skip-cert-verify".to_string(), insecure.clone());
        }
        if let Some(alpn) = tls_obj.get("alpn") {
            config.insert("alpn".to_string(), alpn.clone());
        }
    }
}

/// Convert sing-box transport object to Clash-style transport params on config map.
pub fn singbox_transport_to_clash(
    config: &mut Map<String, Value>,
    transport: &Value,
) {
    if let Some(transport_obj) = transport.as_object() {
        if let Some(transport_type) = transport_obj.get("type").and_then(|v| v.as_str()) {
            config.insert("network".to_string(), Value::String(transport_type.to_string()));
            match transport_type {
                "ws" => {
                    let mut ws_opts = Map::new();
                    if let Some(path) = transport_obj.get("path") { ws_opts.insert("path".to_string(), path.clone()); }
                    if let Some(headers) = transport_obj.get("headers") { ws_opts.insert("headers".to_string(), headers.clone()); }
                    if let Some(ed) = transport_obj.get("max_early_data") { ws_opts.insert("max-early-data".to_string(), ed.clone()); }
                    if let Some(edn) = transport_obj.get("early_data_header_name") { ws_opts.insert("early-data-header-name".to_string(), edn.clone()); }
                    if !ws_opts.is_empty() { config.insert("ws-opts".to_string(), Value::Object(ws_opts)); }
                }
                "grpc" => {
                    let mut grpc_opts = Map::new();
                    if let Some(sn) = transport_obj.get("service_name") { grpc_opts.insert("grpc-service-name".to_string(), sn.clone()); }
                    if !grpc_opts.is_empty() { config.insert("grpc-opts".to_string(), Value::Object(grpc_opts)); }
                }
                "h2" => {
                    let mut h2_opts = Map::new();
                    if let Some(host) = transport_obj.get("host") { h2_opts.insert("host".to_string(), host.clone()); }
                    if let Some(path) = transport_obj.get("path") { h2_opts.insert("path".to_string(), path.clone()); }
                    if !h2_opts.is_empty() { config.insert("h2-opts".to_string(), Value::Object(h2_opts)); }
                }
                "http" => {
                    let mut http_opts = Map::new();
                    if let Some(method) = transport_obj.get("method") { http_opts.insert("method".to_string(), method.clone()); }
                    if let Some(path) = transport_obj.get("path") { http_opts.insert("path".to_string(), path.clone()); }
                    if let Some(headers) = transport_obj.get("headers") { http_opts.insert("headers".to_string(), headers.clone()); }
                    if !http_opts.is_empty() { config.insert("http-opts".to_string(), Value::Object(http_opts)); }
                }
                _ => {}
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tls_roundtrip_clash_to_singbox_to_clash() {
        let mut params = HashMap::new();
        params.insert("sni".to_string(), Value::String("example.com".to_string()));
        params.insert("skip-cert-verify".to_string(), Value::Bool(true));
        params.insert("alpn".to_string(), serde_json::json!(["h2", "http/1.1"]));

        let singbox_tls = clash_tls_to_singbox(&params, true).unwrap();

        let mut clash_config = Map::new();
        singbox_tls_to_clash(&mut clash_config, &singbox_tls);

        assert_eq!(clash_config.get("sni").unwrap().as_str().unwrap(), "example.com");
        assert_eq!(clash_config.get("skip-cert-verify").unwrap().as_bool().unwrap(), true);
    }

    #[test]
    fn test_transport_roundtrip_ws() {
        let mut params = HashMap::new();
        params.insert("network".to_string(), Value::String("ws".to_string()));
        params.insert("ws-opts".to_string(), serde_json::json!({
            "path": "/ws",
            "headers": {"Host": "example.com"}
        }));

        let singbox_transport = clash_transport_to_singbox(&params).unwrap();
        let transport_obj = singbox_transport.as_object().unwrap();
        assert_eq!(transport_obj.get("type").unwrap().as_str().unwrap(), "ws");
        assert_eq!(transport_obj.get("path").unwrap().as_str().unwrap(), "/ws");

        let mut clash_config = Map::new();
        singbox_transport_to_clash(&mut clash_config, &singbox_transport);
        assert_eq!(clash_config.get("network").unwrap().as_str().unwrap(), "ws");
    }

    #[test]
    fn test_singbox_tls_passthrough() {
        let mut params = HashMap::new();
        params.insert("tls".to_string(), serde_json::json!({
            "enabled": true,
            "server_name": "test.com",
            "insecure": false
        }));
        let result = clash_tls_to_singbox(&params, false).unwrap();
        let obj = result.as_object().unwrap();
        assert_eq!(obj.get("server_name").unwrap().as_str().unwrap(), "test.com");
        assert_eq!(obj.get("enabled").unwrap().as_bool().unwrap(), true);
    }

    #[test]
    fn test_singbox_transport_passthrough() {
        let mut params = HashMap::new();
        params.insert("transport".to_string(), serde_json::json!({
            "type": "grpc",
            "service_name": "myservice"
        }));
        let result = clash_transport_to_singbox(&params).unwrap();
        assert_eq!(result["type"], "grpc");
        assert_eq!(result["service_name"], "myservice");
    }
}
