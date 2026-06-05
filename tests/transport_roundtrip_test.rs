//! Tests for transport/TLS conversion roundtrips between Clash and sing-box formats.

use subforge::protocols::transport_converter;
use serde_json::{json, Map};
use std::collections::HashMap;

// ── WebSocket transport roundtrip ───────────────────────────────────────

#[test]
fn test_ws_transport_roundtrip() {
    let mut params = HashMap::new();
    params.insert("network".to_string(), json!("ws"));
    params.insert(
        "ws-opts".to_string(),
        json!({
            "path": "/websocket",
            "headers": {"Host": "cdn.test.com"},
            "max-early-data": 2048,
            "early-data-header-name": "Sec-WebSocket-Protocol"
        }),
    );

    let singbox = transport_converter::clash_transport_to_singbox(&params).unwrap();
    assert_eq!(singbox["type"], "ws");
    assert_eq!(singbox["path"], "/websocket");
    assert_eq!(singbox["max_early_data"], 2048);
    assert_eq!(
        singbox["early_data_header_name"],
        "Sec-WebSocket-Protocol"
    );

    let mut clash_config = Map::new();
    transport_converter::singbox_transport_to_clash(&mut clash_config, &singbox);
    assert_eq!(clash_config["network"], "ws");
    let ws_opts = clash_config["ws-opts"].as_object().unwrap();
    assert_eq!(ws_opts["path"], "/websocket");
    assert_eq!(ws_opts["max-early-data"], 2048);
    assert_eq!(
        ws_opts["early-data-header-name"],
        "Sec-WebSocket-Protocol"
    );
}

// ── gRPC transport roundtrip ────────────────────────────────────────────

#[test]
fn test_grpc_transport_roundtrip() {
    let mut params = HashMap::new();
    params.insert("network".to_string(), json!("grpc"));
    params.insert(
        "grpc-opts".to_string(),
        json!({"grpc-service-name": "mygrpc"}),
    );

    let singbox = transport_converter::clash_transport_to_singbox(&params).unwrap();
    assert_eq!(singbox["type"], "grpc");
    assert_eq!(singbox["service_name"], "mygrpc");

    let mut clash_config = Map::new();
    transport_converter::singbox_transport_to_clash(&mut clash_config, &singbox);
    assert_eq!(clash_config["network"], "grpc");
    let grpc_opts = clash_config["grpc-opts"].as_object().unwrap();
    assert_eq!(grpc_opts["grpc-service-name"], "mygrpc");
}

// ── H2 transport roundtrip ──────────────────────────────────────────────

#[test]
fn test_h2_transport_roundtrip() {
    let mut params = HashMap::new();
    params.insert("network".to_string(), json!("h2"));
    params.insert(
        "h2-opts".to_string(),
        json!({
            "host": ["h2.example.com"],
            "path": "/h2-path"
        }),
    );

    let singbox = transport_converter::clash_transport_to_singbox(&params).unwrap();
    assert_eq!(singbox["type"], "h2");
    assert_eq!(singbox["path"], "/h2-path");
    assert_eq!(singbox["host"], json!(["h2.example.com"]));

    let mut clash_config = Map::new();
    transport_converter::singbox_transport_to_clash(&mut clash_config, &singbox);
    assert_eq!(clash_config["network"], "h2");
    let h2_opts = clash_config["h2-opts"].as_object().unwrap();
    assert_eq!(h2_opts["path"], "/h2-path");
    assert_eq!(h2_opts["host"], json!(["h2.example.com"]));
}

// ── HTTP transport roundtrip ────────────────────────────────────────────

#[test]
fn test_http_transport_roundtrip() {
    let mut params = HashMap::new();
    params.insert("network".to_string(), json!("http"));
    params.insert(
        "http-opts".to_string(),
        json!({
            "method": "GET",
            "path": ["/http-path"],
            "headers": {"X-Custom": "value"}
        }),
    );

    let singbox = transport_converter::clash_transport_to_singbox(&params).unwrap();
    assert_eq!(singbox["type"], "http");
    assert_eq!(singbox["method"], "GET");
    assert_eq!(singbox["path"], json!(["/http-path"]));

    let mut clash_config = Map::new();
    transport_converter::singbox_transport_to_clash(&mut clash_config, &singbox);
    assert_eq!(clash_config["network"], "http");
    let http_opts = clash_config["http-opts"].as_object().unwrap();
    assert_eq!(http_opts["method"], "GET");
    assert_eq!(http_opts["path"], json!(["/http-path"]));
}

// ── TLS roundtrip tests ─────────────────────────────────────────────────

#[test]
fn test_tls_roundtrip_trojan_style() {
    let mut params = HashMap::new();
    params.insert("sni".to_string(), json!("trojan.example.com"));
    params.insert("skip-cert-verify".to_string(), json!(true));
    params.insert("alpn".to_string(), json!(["h2", "http/1.1"]));

    let singbox_tls = transport_converter::clash_tls_to_singbox(&params, true).unwrap();
    let tls_obj = singbox_tls.as_object().unwrap();
    assert_eq!(tls_obj["enabled"], true);
    assert_eq!(tls_obj["server_name"], "trojan.example.com");
    assert_eq!(tls_obj["insecure"], true);
    assert_eq!(tls_obj["alpn"], json!(["h2", "http/1.1"]));

    let mut clash_config = Map::new();
    transport_converter::singbox_tls_to_clash(&mut clash_config, &singbox_tls);
    assert_eq!(clash_config["sni"], "trojan.example.com");
    assert_eq!(clash_config["skip-cert-verify"], true);
    assert_eq!(clash_config["alpn"], json!(["h2", "http/1.1"]));
}

#[test]
fn test_tls_with_servername_key() {
    // Clash uses both "sni" and "servername" for TLS server name
    let mut params = HashMap::new();
    params.insert("servername".to_string(), json!("alt.example.com"));
    params.insert("tls".to_string(), json!(true));

    let singbox_tls = transport_converter::clash_tls_to_singbox(&params, false).unwrap();
    let tls_obj = singbox_tls.as_object().unwrap();
    assert_eq!(tls_obj["enabled"], true);
    assert_eq!(tls_obj["server_name"], "alt.example.com");
}

#[test]
fn test_singbox_tls_object_passthrough() {
    let mut params = HashMap::new();
    params.insert(
        "tls".to_string(),
        json!({
            "enabled": true,
            "server_name": "pass.example.com",
            "insecure": false,
            "alpn": ["h2"]
        }),
    );

    let result = transport_converter::clash_tls_to_singbox(&params, false).unwrap();
    let obj = result.as_object().unwrap();
    assert_eq!(obj["server_name"], "pass.example.com");
    assert_eq!(obj["insecure"], false);
    assert_eq!(obj["alpn"], json!(["h2"]));
    assert_eq!(obj["enabled"], true);
}

#[test]
fn test_tls_disabled_returns_none() {
    // When always_enabled is false and there is no tls key, should return None
    let params = HashMap::new();
    let result = transport_converter::clash_tls_to_singbox(&params, false);
    assert!(result.is_none());
}

#[test]
fn test_tls_disabled_bool_returns_none() {
    // When tls is explicitly false and always_enabled is false
    let mut params = HashMap::new();
    params.insert("tls".to_string(), json!(false));
    let result = transport_converter::clash_tls_to_singbox(&params, false);
    assert!(result.is_none());
}

#[test]
fn test_tls_always_enabled_ignores_tls_false() {
    // Trojan always has TLS, so even with tls: false, always_enabled=true should produce TLS config
    let mut params = HashMap::new();
    params.insert("tls".to_string(), json!(false));
    params.insert("sni".to_string(), json!("trojan.example.com"));
    let result = transport_converter::clash_tls_to_singbox(&params, true).unwrap();
    let obj = result.as_object().unwrap();
    assert_eq!(obj["enabled"], true);
    assert_eq!(obj["server_name"], "trojan.example.com");
}

// ── Transport passthrough ───────────────────────────────────────────────

#[test]
fn test_singbox_transport_object_passthrough() {
    let mut params = HashMap::new();
    params.insert(
        "transport".to_string(),
        json!({
            "type": "grpc",
            "service_name": "myservice"
        }),
    );
    let result = transport_converter::clash_transport_to_singbox(&params).unwrap();
    assert_eq!(result["type"], "grpc");
    assert_eq!(result["service_name"], "myservice");
}

#[test]
fn test_no_network_returns_none() {
    // Without a "network" key and without "transport", should return None
    let params = HashMap::new();
    let result = transport_converter::clash_transport_to_singbox(&params);
    assert!(result.is_none());
}

#[test]
fn test_unknown_network_type_with_no_opts() {
    // Unknown network type with no matching opts -> should return None (only "type" key, len == 1)
    let mut params = HashMap::new();
    params.insert("network".to_string(), json!("quic"));
    let result = transport_converter::clash_transport_to_singbox(&params);
    assert!(result.is_none());
}

// ── Singbox TLS to Clash conversion ─────────────────────────────────────

#[test]
fn test_singbox_tls_to_clash_full() {
    let tls = json!({
        "enabled": true,
        "server_name": "example.com",
        "insecure": false,
        "alpn": ["h2", "http/1.1"]
    });
    let mut config = Map::new();
    transport_converter::singbox_tls_to_clash(&mut config, &tls);
    assert_eq!(config["sni"], "example.com");
    assert_eq!(config["skip-cert-verify"], false);
    assert_eq!(config["alpn"], json!(["h2", "http/1.1"]));
}

#[test]
fn test_singbox_tls_to_clash_minimal() {
    // Only server_name present
    let tls = json!({
        "server_name": "minimal.com"
    });
    let mut config = Map::new();
    transport_converter::singbox_tls_to_clash(&mut config, &tls);
    assert_eq!(config["sni"], "minimal.com");
    assert!(config.get("skip-cert-verify").is_none());
    assert!(config.get("alpn").is_none());
}

#[test]
fn test_singbox_tls_to_clash_non_object_noop() {
    // If tls is not an object, singbox_tls_to_clash should be a no-op
    let tls = json!(true);
    let mut config = Map::new();
    transport_converter::singbox_tls_to_clash(&mut config, &tls);
    assert!(config.is_empty());
}
