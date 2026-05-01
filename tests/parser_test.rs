//! Tests for parser extraction of individual proxy types from strongly-typed configs.

use proxy_convert::core::source::Protocol;
use proxy_convert::protocols::{clash, singbox, ProxyParams};
use proxy_convert::protocols::source::{Config, Source};

fn make_source(config: Config, source_type: Protocol) -> Source {
    use proxy_convert::core::source::SourceMeta;
    Source {
        meta: SourceMeta {
            name: Some("test".into()),
            source_type,
            source: "test".into(),
            format: None,
            flag: None,
        },
        config,
    }
}

// ── Sing-box extraction tests ───────────────────────────────────────────

#[test]
fn test_extract_singbox_trojan_with_tls() {
    let config: singbox::Config = serde_json::from_value(serde_json::json!({
        "inbounds": [],
        "outbounds": [
            {
                "type": "trojan",
                "tag": "trojan-test",
                "server": "example.com",
                "server_port": 443,
                "password": "secret",
                "tls": { "enabled": true, "server_name": "example.com", "insecure": true }
            }
        ]
    }))
    .unwrap();
    let source = make_source(Config::SingBox(config), Protocol::SingBox);
    let servers = source.extract_servers().unwrap();
    assert_eq!(servers.len(), 1);
    assert_eq!(servers[0].protocol, "trojan");
    assert_eq!(servers[0].password.as_deref(), Some("secret"));
    match &servers[0].params {
        ProxyParams::Trojan { tls, .. } => {
            let tls = tls.as_ref().unwrap();
            assert!(tls.enabled);
            assert_eq!(tls.server_name.as_deref(), Some("example.com"));
            assert_eq!(tls.insecure, Some(true));
        }
        _ => panic!("Expected Trojan params"),
    }
}

#[test]
fn test_extract_singbox_block_and_direct_skipped() {
    let config: singbox::Config = serde_json::from_value(serde_json::json!({
        "inbounds": [],
        "outbounds": [
            {"type": "block", "tag": "REJECT"},
            {"type": "direct", "tag": "DIRECT"},
            {"type": "shadowsocks", "tag": "ss-test", "server": "1.1.1.1", "server_port": 8388, "method": "aes-256-gcm", "password": "test"}
        ]
    }))
    .unwrap();
    let source = make_source(Config::SingBox(config), Protocol::SingBox);
    let servers = source.extract_servers().unwrap();
    // Only the shadowsocks proxy should be extracted (block and direct are skipped)
    assert_eq!(servers.len(), 1);
    assert_eq!(servers[0].protocol, "shadowsocks");
}

#[test]
fn test_extract_singbox_dns_outbound_skipped() {
    let config: singbox::Config = serde_json::from_value(serde_json::json!({
        "inbounds": [],
        "outbounds": [
            {"type": "dns", "tag": "dns-out"},
            {"type": "block", "tag": "REJECT"},
            {"type": "vmess", "tag": "vmess1", "server": "3.3.3.3", "server_port": 443, "uuid": "some-uuid", "security": "auto", "alter_id": 0}
        ]
    }))
    .unwrap();
    let source = make_source(Config::SingBox(config), Protocol::SingBox);
    let servers = source.extract_servers().unwrap();
    // Only vmess should be extracted; dns and block are non-proxy outbounds
    assert_eq!(servers.len(), 1);
    assert_eq!(servers[0].protocol, "vmess");
    assert_eq!(servers[0].name, "vmess1");
}

#[test]
fn test_extract_singbox_selector_and_urltest_skipped() {
    let config: singbox::Config = serde_json::from_value(serde_json::json!({
        "inbounds": [],
        "outbounds": [
            {"type": "selector", "tag": "proxy", "outbounds": ["ss1"]},
            {"type": "urltest", "tag": "auto", "outbounds": ["ss1"]},
            {"type": "shadowsocks", "tag": "ss1", "server": "1.1.1.1", "server_port": 8388, "method": "aes-256-gcm", "password": "pw"}
        ]
    }))
    .unwrap();
    let source = make_source(Config::SingBox(config), Protocol::SingBox);
    let servers = source.extract_servers().unwrap();
    assert_eq!(servers.len(), 1);
    assert_eq!(servers[0].protocol, "shadowsocks");
}

#[test]
fn test_extract_singbox_shadowsocks_params() {
    let config: singbox::Config = serde_json::from_value(serde_json::json!({
        "inbounds": [],
        "outbounds": [
            {
                "type": "shadowsocks",
                "tag": "ss-full",
                "server": "10.0.0.1",
                "server_port": 8388,
                "method": "2022-blake3-aes-256-gcm",
                "password": "secure-pass"
            }
        ]
    }))
    .unwrap();
    let source = make_source(Config::SingBox(config), Protocol::SingBox);
    let servers = source.extract_servers().unwrap();
    assert_eq!(servers.len(), 1);
    assert_eq!(servers[0].server, "10.0.0.1");
    assert_eq!(servers[0].port, 8388);
    assert_eq!(servers[0].method.as_deref(), Some("2022-blake3-aes-256-gcm"));
    assert_eq!(servers[0].password.as_deref(), Some("secure-pass"));
    match &servers[0].params {
        ProxyParams::Shadowsocks { cipher, .. } => {
            assert_eq!(cipher, "2022-blake3-aes-256-gcm");
        }
        _ => panic!("Expected Shadowsocks params"),
    }
}

#[test]
fn test_extract_singbox_vmess_with_transport() {
    let config: singbox::Config = serde_json::from_value(serde_json::json!({
        "inbounds": [],
        "outbounds": [
            {
                "type": "vmess",
                "tag": "vmess-ws",
                "server": "cdn.example.com",
                "server_port": 443,
                "uuid": "test-uuid-123",
                "security": "auto",
                "alter_id": 0,
                "tls": { "enabled": true, "server_name": "cdn.example.com" },
                "transport": { "type": "ws", "path": "/ws-path" }
            }
        ]
    }))
    .unwrap();
    let source = make_source(Config::SingBox(config), Protocol::SingBox);
    let servers = source.extract_servers().unwrap();
    assert_eq!(servers.len(), 1);
    assert_eq!(servers[0].protocol, "vmess");
    match &servers[0].params {
        ProxyParams::Vmess {
            uuid,
            tls,
            transport,
            ..
        } => {
            assert_eq!(uuid, "test-uuid-123");
            let tls = tls.as_ref().unwrap();
            assert!(tls.enabled);
            assert_eq!(tls.server_name.as_deref(), Some("cdn.example.com"));
            let tp = transport.as_ref().unwrap();
            assert_eq!(tp.transport_type, "ws");
            assert_eq!(tp.path.as_deref(), Some("/ws-path"));
        }
        _ => panic!("Expected Vmess params"),
    }
}

// ── Clash extraction tests ──────────────────────────────────────────────

#[test]
fn test_extract_clash_vmess() {
    let config: clash::Config = serde_json::from_value(serde_json::json!({
        "proxies": [{
            "name": "vmess-test",
            "type": "vmess",
            "server": "2.2.2.2",
            "port": 443,
            "uuid": "test-uuid",
            "alterId": 0,
            "cipher": "auto",
            "tls": true,
            "servername": "cdn.example.com",
            "network": "ws",
            "ws-opts": { "path": "/ws", "headers": { "Host": "cdn.example.com" } }
        }]
    }))
    .unwrap();
    let source = make_source(Config::Clash(config), Protocol::Clash);
    let servers = source.extract_servers().unwrap();
    assert_eq!(servers.len(), 1);
    assert_eq!(servers[0].protocol, "vmess");
    match &servers[0].params {
        ProxyParams::Vmess {
            uuid,
            tls,
            transport,
            ..
        } => {
            assert_eq!(uuid, "test-uuid");
            assert!(tls.is_some());
            assert_eq!(
                tls.as_ref().unwrap().server_name.as_deref(),
                Some("cdn.example.com")
            );
            assert!(transport.is_some());
            assert_eq!(transport.as_ref().unwrap().transport_type, "ws");
            assert_eq!(transport.as_ref().unwrap().path.as_deref(), Some("/ws"));
        }
        _ => panic!("Expected Vmess params"),
    }
}

#[test]
fn test_extract_clash_trojan() {
    let config: clash::Config = serde_json::from_value(serde_json::json!({
        "proxies": [{
            "name": "trojan-test",
            "type": "trojan",
            "server": "3.3.3.3",
            "port": 443,
            "password": "trojan-pw",
            "sni": "trojan.example.com",
            "skip-cert-verify": false,
            "alpn": ["h2", "http/1.1"]
        }]
    }))
    .unwrap();
    let source = make_source(Config::Clash(config), Protocol::Clash);
    let servers = source.extract_servers().unwrap();
    assert_eq!(servers.len(), 1);
    assert_eq!(servers[0].protocol, "trojan");
    assert_eq!(servers[0].password.as_deref(), Some("trojan-pw"));
    match &servers[0].params {
        ProxyParams::Trojan { tls, .. } => {
            let tls = tls.as_ref().unwrap();
            assert!(tls.enabled);
            assert_eq!(tls.server_name.as_deref(), Some("trojan.example.com"));
            assert_eq!(tls.insecure, Some(false));
            assert_eq!(
                tls.alpn.as_ref().unwrap(),
                &vec!["h2".to_string(), "http/1.1".to_string()]
            );
        }
        _ => panic!("Expected Trojan params"),
    }
}

#[test]
fn test_extract_clash_shadowsocks() {
    let config: clash::Config = serde_json::from_value(serde_json::json!({
        "proxies": [{
            "name": "ss-test",
            "type": "ss",
            "server": "4.4.4.4",
            "port": 8388,
            "cipher": "aes-256-gcm",
            "password": "ss-pw",
            "udp": true
        }]
    }))
    .unwrap();
    let source = make_source(Config::Clash(config), Protocol::Clash);
    let servers = source.extract_servers().unwrap();
    assert_eq!(servers.len(), 1);
    // "ss" from Clash should be normalized to "shadowsocks"
    assert_eq!(servers[0].protocol, "shadowsocks");
    assert_eq!(servers[0].password.as_deref(), Some("ss-pw"));
    assert_eq!(servers[0].method.as_deref(), Some("aes-256-gcm"));
    match &servers[0].params {
        ProxyParams::Shadowsocks { cipher, udp, .. } => {
            assert_eq!(cipher, "aes-256-gcm");
            assert_eq!(*udp, Some(true));
        }
        _ => panic!("Expected Shadowsocks params"),
    }
}

#[test]
fn test_extract_clash_multiple_proxies() {
    let config: clash::Config = serde_json::from_value(serde_json::json!({
        "proxies": [
            {
                "name": "ss-1",
                "type": "ss",
                "server": "1.1.1.1",
                "port": 8388,
                "cipher": "aes-256-gcm",
                "password": "pw1"
            },
            {
                "name": "vmess-1",
                "type": "vmess",
                "server": "2.2.2.2",
                "port": 443,
                "uuid": "uuid-1",
                "alterId": 0,
                "cipher": "auto"
            },
            {
                "name": "trojan-1",
                "type": "trojan",
                "server": "3.3.3.3",
                "port": 443,
                "password": "pw3",
                "alpn": []
            }
        ]
    }))
    .unwrap();
    let source = make_source(Config::Clash(config), Protocol::Clash);
    let servers = source.extract_servers().unwrap();
    assert_eq!(servers.len(), 3);
    assert_eq!(servers[0].protocol, "shadowsocks");
    assert_eq!(servers[1].protocol, "vmess");
    assert_eq!(servers[2].protocol, "trojan");
}
