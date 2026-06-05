//! Tests for parser extraction of individual proxy types from strongly-typed configs.

use proxy_convert::core::source::Protocol;
use proxy_convert::protocols::{clash, singbox, ProxyParams};
use proxy_convert::protocols::source::{Config, Source};

fn make_source(config: Config, source_type: Protocol) -> Source {
    use proxy_convert::core::source::{SourceLocation, SourceMeta};
    Source {
        meta: SourceMeta {
            name: Some("test".into()),
            source_type,
            location: SourceLocation::File("test".into()),
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

// ── AnyTLS extraction tests ──────────────────────────────────────────────

#[test]
fn test_extract_clash_anytls() {
    let config: clash::Config = serde_json::from_value(serde_json::json!({
        "proxies": [{
            "name": "anytls-test",
            "type": "anytls",
            "server": "1.2.3.4",
            "port": 443,
            "password": "secret",
            "udp": true,
            "sni": "example.com",
            "alpn": ["h2", "http/1.1"],
            "skip-cert-verify": true,
            "client-fingerprint": "chrome",
            "idle-session-check-interval": 30,
            "idle-session-timeout": 30,
            "min-idle-session": 5
        }]
    }))
    .unwrap();
    let source = make_source(Config::Clash(config), Protocol::Clash);
    let servers = source.extract_servers().unwrap();
    assert_eq!(servers.len(), 1);
    assert_eq!(servers[0].protocol, "anytls");
    assert_eq!(servers[0].password.as_deref(), Some("secret"));
    match &servers[0].params {
        ProxyParams::AnyTls {
            tls,
            min_idle_session,
            idle_session_timeout,
            ..
        } => {
            let tls = tls.as_ref().expect("tls");
            assert!(tls.enabled);
            assert_eq!(tls.server_name.as_deref(), Some("example.com"));
            assert_eq!(tls.insecure, Some(true));
            assert_eq!(*min_idle_session, Some(5));
            assert_eq!(idle_session_timeout.as_ref().and_then(|v| v.as_u64()), Some(30));
        }
        _ => panic!("Expected AnyTls params"),
    }
}

#[test]
fn test_extract_singbox_anytls() {
    let config: singbox::Config = serde_json::from_value(serde_json::json!({
        "inbounds": [],
        "outbounds": [
            {
                "type": "anytls",
                "tag": "anytls-out",
                "server": "1.2.3.4",
                "server_port": 8443,
                "password": "secret",
                "idle_session_check_interval": "30s",
                "idle_session_timeout": "30s",
                "min_idle_session": 5,
                "tls": { "enabled": true, "server_name": "example.com", "insecure": false }
            }
        ]
    }))
    .unwrap();
    let source = make_source(Config::SingBox(config), Protocol::SingBox);
    let servers = source.extract_servers().unwrap();
    assert_eq!(servers.len(), 1);
    assert_eq!(servers[0].protocol, "anytls");
    assert_eq!(servers[0].password.as_deref(), Some("secret"));
    assert_eq!(servers[0].port, 8443);
    match &servers[0].params {
        ProxyParams::AnyTls { tls, min_idle_session, .. } => {
            let tls = tls.as_ref().expect("tls");
            assert!(tls.enabled);
            assert_eq!(tls.server_name.as_deref(), Some("example.com"));
            assert_eq!(*min_idle_session, Some(5));
        }
        _ => panic!("Expected AnyTls params"),
    }
}

#[test]
fn test_clash_anytls_to_singbox_node_config() {
    use proxy_convert::protocols::singbox::template_processor::SingboxProcessor;
    use proxy_convert::protocols::ProtocolProcessor;

    let config: clash::Config = serde_json::from_value(serde_json::json!({
        "proxies": [{
            "name": "anytls-1",
            "type": "anytls",
            "server": "host.example.com",
            "port": 443,
            "password": "pw",
            "sni": "host.example.com",
            "skip-cert-verify": false,
            "alpn": ["h2"],
            "idle-session-check-interval": 30,
            "idle-session-timeout": 30,
            "min-idle-session": 0
        }]
    }))
    .unwrap();
    let source = make_source(Config::Clash(config), Protocol::Clash);
    let servers = source.extract_servers().unwrap();
    let processor = SingboxProcessor;
    let node_json = processor.create_node_config(&servers[0]);
    let parsed: serde_json::Value = serde_json::from_str(&node_json).unwrap();
    assert_eq!(parsed["type"], "anytls");
    assert_eq!(parsed["server"], "host.example.com");
    assert_eq!(parsed["server_port"], 443);
    assert_eq!(parsed["password"], "pw");
    assert_eq!(parsed["tls"]["enabled"], true);
    assert_eq!(parsed["tls"]["server_name"], "host.example.com");
    assert_eq!(parsed["tls"]["alpn"][0], "h2");
    assert_eq!(parsed["idle_session_check_interval"], "30s");
    assert_eq!(parsed["idle_session_timeout"], "30s");
    assert_eq!(parsed["min_idle_session"], 0);
}

#[test]
fn test_parse_anytls_url() {
    use proxy_convert::protocols::subscription::parse_proxy_url;
    let s = parse_proxy_url("anytls://letmein@example.com:8443/?sni=real.example.com&insecure=1#node1")
        .unwrap()
        .expect("parsed");
    assert_eq!(s.protocol, "anytls");
    assert_eq!(s.server, "example.com");
    assert_eq!(s.port, 8443);
    assert_eq!(s.password.as_deref(), Some("letmein"));
    assert_eq!(s.name, "node1");
    match &s.params {
        ProxyParams::AnyTls { tls, .. } => {
            let tls = tls.as_ref().expect("tls");
            assert_eq!(tls.server_name.as_deref(), Some("real.example.com"));
            assert_eq!(tls.insecure, Some(true));
        }
        _ => panic!("Expected AnyTls"),
    }

    // Default port
    let s2 = parse_proxy_url("anytls://letmein@example.com/?sni=real.example.com")
        .unwrap()
        .expect("parsed");
    assert_eq!(s2.port, 443);
}

// ── VLESS / Hysteria2 / Hysteria / TUIC / WireGuard tests ───────────────

#[test]
fn test_extract_clash_vless_with_reality() {
    let config: clash::Config = serde_json::from_value(serde_json::json!({
        "proxies": [{
            "name": "vless-reality",
            "type": "vless",
            "server": "1.2.3.4",
            "port": 443,
            "uuid": "00000000-0000-0000-0000-000000000001",
            "flow": "xtls-rprx-vision",
            "tls": true,
            "servername": "example.com",
            "client-fingerprint": "chrome",
            "reality-opts": {
                "public-key": "abc",
                "short-id": "ff"
            },
            "network": "tcp"
        }]
    }))
    .unwrap();
    let source = make_source(Config::Clash(config), Protocol::Clash);
    let servers = source.extract_servers().unwrap();
    assert_eq!(servers.len(), 1);
    assert_eq!(servers[0].protocol, "vless");
    match &servers[0].params {
        ProxyParams::Vless { uuid, flow, tls, .. } => {
            assert_eq!(uuid, "00000000-0000-0000-0000-000000000001");
            assert_eq!(flow.as_deref(), Some("xtls-rprx-vision"));
            assert!(tls.is_some());
        }
        _ => panic!("Expected Vless params"),
    }
}

#[test]
fn test_clash_vless_reality_to_singbox_emits_reality() {
    use proxy_convert::protocols::singbox::template_processor::SingboxProcessor;
    use proxy_convert::protocols::ProtocolProcessor;

    let config: clash::Config = serde_json::from_value(serde_json::json!({
        "proxies": [{
            "name": "vless-reality",
            "type": "vless",
            "server": "1.2.3.4",
            "port": 443,
            "uuid": "00000000-0000-0000-0000-000000000001",
            "flow": "xtls-rprx-vision",
            "tls": true,
            "servername": "example.com",
            "client-fingerprint": "chrome",
            "reality-opts": {"public-key": "PK", "short-id": "SID"}
        }]
    }))
    .unwrap();
    let source = make_source(Config::Clash(config), Protocol::Clash);
    let servers = source.extract_servers().unwrap();
    let p = SingboxProcessor;
    let json: serde_json::Value = serde_json::from_str(&p.create_node_config(&servers[0])).unwrap();
    assert_eq!(json["type"], "vless");
    assert_eq!(json["uuid"], "00000000-0000-0000-0000-000000000001");
    assert_eq!(json["flow"], "xtls-rprx-vision");
    assert_eq!(json["tls"]["enabled"], true);
    assert_eq!(json["tls"]["server_name"], "example.com");
    assert_eq!(json["tls"]["reality"]["enabled"], true);
    assert_eq!(json["tls"]["reality"]["public_key"], "PK");
    assert_eq!(json["tls"]["reality"]["short_id"], "SID");
    assert_eq!(json["tls"]["utls"]["fingerprint"], "chrome");
}

#[test]
fn test_extract_clash_hysteria2() {
    let config: clash::Config = serde_json::from_value(serde_json::json!({
        "proxies": [{
            "name": "hy2",
            "type": "hysteria2",
            "server": "1.2.3.4",
            "port": 443,
            "password": "pw",
            "up": "30 Mbps",
            "down": "200 Mbps",
            "obfs": "salamander",
            "obfs-password": "obfs-pw",
            "sni": "host.com",
            "skip-cert-verify": true,
            "alpn": ["h3"]
        }]
    }))
    .unwrap();
    let source = make_source(Config::Clash(config), Protocol::Clash);
    let servers = source.extract_servers().unwrap();
    assert_eq!(servers.len(), 1);
    assert_eq!(servers[0].protocol, "hysteria2");
    match &servers[0].params {
        ProxyParams::Hysteria2 {
            obfs,
            obfs_password,
            up_mbps,
            down_mbps,
            tls,
            ..
        } => {
            assert_eq!(obfs.as_deref(), Some("salamander"));
            assert_eq!(obfs_password.as_deref(), Some("obfs-pw"));
            assert_eq!(*up_mbps, Some(30));
            assert_eq!(*down_mbps, Some(200));
            assert_eq!(tls.as_ref().unwrap().server_name.as_deref(), Some("host.com"));
        }
        _ => panic!("Expected Hysteria2 params"),
    }
}

#[test]
fn test_clash_hysteria2_to_singbox_emits_obfs_and_mbps() {
    use proxy_convert::protocols::singbox::template_processor::SingboxProcessor;
    use proxy_convert::protocols::ProtocolProcessor;

    let config: clash::Config = serde_json::from_value(serde_json::json!({
        "proxies": [{
            "name": "hy2",
            "type": "hysteria2",
            "server": "host.com",
            "port": 443,
            "password": "pw",
            "up": "30 Mbps",
            "down": "200 Mbps",
            "obfs": "salamander",
            "obfs-password": "obfs-pw",
            "sni": "host.com"
        }]
    }))
    .unwrap();
    let source = make_source(Config::Clash(config), Protocol::Clash);
    let servers = source.extract_servers().unwrap();
    let p = SingboxProcessor;
    let json: serde_json::Value = serde_json::from_str(&p.create_node_config(&servers[0])).unwrap();
    assert_eq!(json["type"], "hysteria2");
    assert_eq!(json["password"], "pw");
    assert_eq!(json["up_mbps"], 30);
    assert_eq!(json["down_mbps"], 200);
    assert_eq!(json["obfs"]["type"], "salamander");
    assert_eq!(json["obfs"]["password"], "obfs-pw");
    assert_eq!(json["tls"]["enabled"], true);
    assert_eq!(json["tls"]["server_name"], "host.com");
}

#[test]
fn test_extract_clash_hysteria_v1() {
    let config: clash::Config = serde_json::from_value(serde_json::json!({
        "proxies": [{
            "name": "hy",
            "type": "hysteria",
            "server": "h1.example.com",
            "port": 443,
            "auth-str": "pwd",
            "up": "30",
            "down": "200",
            "obfs": "obfs-str",
            "alpn": ["h3"],
            "protocol": "udp",
            "sni": "h1.example.com"
        }]
    }))
    .unwrap();
    let source = make_source(Config::Clash(config), Protocol::Clash);
    let servers = source.extract_servers().unwrap();
    assert_eq!(servers.len(), 1);
    assert_eq!(servers[0].protocol, "hysteria");
    match &servers[0].params {
        ProxyParams::Hysteria { auth_str, obfs, up_mbps, .. } => {
            assert_eq!(auth_str.as_deref(), Some("pwd"));
            assert_eq!(obfs.as_deref(), Some("obfs-str"));
            assert_eq!(*up_mbps, Some(30));
        }
        _ => panic!("Expected Hysteria params"),
    }
}

#[test]
fn test_clash_hysteria_v1_to_singbox_uses_auth_str() {
    use proxy_convert::protocols::singbox::template_processor::SingboxProcessor;
    use proxy_convert::protocols::ProtocolProcessor;

    let config: clash::Config = serde_json::from_value(serde_json::json!({
        "proxies": [{
            "name": "hy",
            "type": "hysteria",
            "server": "h.com",
            "port": 443,
            "auth-str": "pwd",
            "up": "30 Mbps",
            "down": "200 Mbps",
            "sni": "h.com"
        }]
    }))
    .unwrap();
    let source = make_source(Config::Clash(config), Protocol::Clash);
    let servers = source.extract_servers().unwrap();
    let p = SingboxProcessor;
    let json: serde_json::Value = serde_json::from_str(&p.create_node_config(&servers[0])).unwrap();
    assert_eq!(json["type"], "hysteria");
    assert_eq!(json["auth_str"], "pwd");
    assert!(json.get("password").is_none(), "hysteria should drop password key");
    assert_eq!(json["up_mbps"], 30);
    assert_eq!(json["down_mbps"], 200);
}

#[test]
fn test_extract_clash_tuic_v5() {
    let config: clash::Config = serde_json::from_value(serde_json::json!({
        "proxies": [{
            "name": "tuic",
            "type": "tuic",
            "server": "tuic.example.com",
            "port": 443,
            "uuid": "00000000-0000-0000-0000-000000000001",
            "password": "pw",
            "congestion-controller": "bbr",
            "udp-relay-mode": "native",
            "reduce-rtt": true,
            "heartbeat-interval": 10000,
            "alpn": ["h3"],
            "sni": "tuic.example.com",
            "skip-cert-verify": true
        }]
    }))
    .unwrap();
    let source = make_source(Config::Clash(config), Protocol::Clash);
    let servers = source.extract_servers().unwrap();
    assert_eq!(servers.len(), 1);
    assert_eq!(servers[0].protocol, "tuic");
    match &servers[0].params {
        ProxyParams::Tuic { uuid, congestion_control, udp_relay_mode, zero_rtt_handshake, heartbeat, .. } => {
            assert_eq!(uuid.as_deref(), Some("00000000-0000-0000-0000-000000000001"));
            assert_eq!(congestion_control.as_deref(), Some("bbr"));
            assert_eq!(udp_relay_mode.as_deref(), Some("native"));
            assert_eq!(*zero_rtt_handshake, Some(true));
            assert_eq!(heartbeat.as_deref(), Some("10000ms"));
        }
        _ => panic!("Expected Tuic params"),
    }
}

#[test]
fn test_clash_tuic_to_singbox_emits_v5_fields() {
    use proxy_convert::protocols::singbox::template_processor::SingboxProcessor;
    use proxy_convert::protocols::ProtocolProcessor;

    let config: clash::Config = serde_json::from_value(serde_json::json!({
        "proxies": [{
            "name": "tuic",
            "type": "tuic",
            "server": "h.com",
            "port": 443,
            "uuid": "U",
            "password": "P",
            "congestion-controller": "bbr",
            "udp-relay-mode": "native",
            "heartbeat-interval": 10000,
            "sni": "h.com"
        }]
    }))
    .unwrap();
    let source = make_source(Config::Clash(config), Protocol::Clash);
    let servers = source.extract_servers().unwrap();
    let p = SingboxProcessor;
    let json: serde_json::Value = serde_json::from_str(&p.create_node_config(&servers[0])).unwrap();
    assert_eq!(json["type"], "tuic");
    assert_eq!(json["uuid"], "U");
    assert_eq!(json["password"], "P");
    assert_eq!(json["congestion_control"], "bbr");
    assert_eq!(json["udp_relay_mode"], "native");
    assert_eq!(json["heartbeat"], "10000ms");
}

#[test]
fn test_extract_clash_wireguard_simplified() {
    let config: clash::Config = serde_json::from_value(serde_json::json!({
        "proxies": [{
            "name": "wg",
            "type": "wireguard",
            "server": "1.2.3.4",
            "port": 51820,
            "ip": "172.16.0.2",
            "ipv6": "fd::1",
            "private-key": "PRIV",
            "public-key": "PUB",
            "allowed-ips": ["0.0.0.0/0"],
            "udp": true,
            "mtu": 1408
        }]
    }))
    .unwrap();
    let source = make_source(Config::Clash(config), Protocol::Clash);
    let servers = source.extract_servers().unwrap();
    assert_eq!(servers.len(), 1);
    assert_eq!(servers[0].protocol, "wireguard");
    assert_eq!(servers[0].server, "1.2.3.4");
    assert_eq!(servers[0].port, 51820);
    match &servers[0].params {
        ProxyParams::WireGuard { private_key, local_addresses, peers, mtu, .. } => {
            assert_eq!(private_key, "PRIV");
            assert!(local_addresses.contains(&"172.16.0.2/32".to_string()));
            assert!(local_addresses.contains(&"fd::1/128".to_string()));
            assert_eq!(*mtu, Some(1408));
            assert_eq!(peers.len(), 1);
            assert_eq!(peers[0].server, "1.2.3.4");
            assert_eq!(peers[0].public_key, "PUB");
        }
        _ => panic!("Expected WireGuard params"),
    }
}

#[test]
fn test_clash_wireguard_full_peers_to_singbox() {
    use proxy_convert::protocols::singbox::template_processor::SingboxProcessor;
    use proxy_convert::protocols::ProtocolProcessor;

    let config: clash::Config = serde_json::from_value(serde_json::json!({
        "proxies": [{
            "name": "wg",
            "type": "wireguard",
            "ip": "172.16.0.2",
            "private-key": "PRIV",
            "peers": [
                {
                    "server": "1.2.3.4",
                    "port": 51820,
                    "public-key": "PUB",
                    "allowed-ips": ["0.0.0.0/0"],
                    "reserved": [209, 98, 59]
                }
            ]
        }]
    }))
    .unwrap();
    let source = make_source(Config::Clash(config), Protocol::Clash);
    let servers = source.extract_servers().unwrap();
    let p = SingboxProcessor;
    let json: serde_json::Value = serde_json::from_str(&p.create_node_config(&servers[0])).unwrap();
    assert_eq!(json["type"], "wireguard");
    assert_eq!(json["private_key"], "PRIV");
    assert_eq!(json["local_address"][0], "172.16.0.2/32");
    assert_eq!(json["peers"][0]["server"], "1.2.3.4");
    assert_eq!(json["peers"][0]["server_port"], 51820);
    assert_eq!(json["peers"][0]["public_key"], "PUB");
    assert_eq!(json["peers"][0]["allowed_ips"][0], "0.0.0.0/0");
    assert_eq!(json["peers"][0]["reserved"][0], 209);
}

#[test]
fn test_parse_hysteria_url() {
    use proxy_convert::protocols::subscription::parse_proxy_url;
    let s = parse_proxy_url("hysteria://h.example.com:443?auth=pwd&peer=h.com&upmbps=30&downmbps=200&obfs=mystic#hy1")
        .unwrap()
        .expect("parsed");
    assert_eq!(s.protocol, "hysteria");
    assert_eq!(s.server, "h.example.com");
    assert_eq!(s.port, 443);
    assert_eq!(s.password.as_deref(), Some("pwd"));
    match &s.params {
        ProxyParams::Hysteria { auth_str, up_mbps, down_mbps, obfs, .. } => {
            assert_eq!(auth_str.as_deref(), Some("pwd"));
            assert_eq!(*up_mbps, Some(30));
            assert_eq!(*down_mbps, Some(200));
            assert_eq!(obfs.as_deref(), Some("mystic"));
        }
        _ => panic!("Expected Hysteria"),
    }
}

#[test]
fn test_parse_tuic_v5_url() {
    use proxy_convert::protocols::subscription::parse_proxy_url;
    let s = parse_proxy_url("tuic://U:P@host.com:443/?sni=host.com&congestion_control=bbr&udp_relay_mode=native&allow_insecure=1#tuic1")
        .unwrap()
        .expect("parsed");
    assert_eq!(s.protocol, "tuic");
    assert_eq!(s.server, "host.com");
    assert_eq!(s.port, 443);
    assert_eq!(s.password.as_deref(), Some("P"));
    match &s.params {
        ProxyParams::Tuic { uuid, congestion_control, udp_relay_mode, tls, .. } => {
            assert_eq!(uuid.as_deref(), Some("U"));
            assert_eq!(congestion_control.as_deref(), Some("bbr"));
            assert_eq!(udp_relay_mode.as_deref(), Some("native"));
            let t = tls.as_ref().unwrap();
            assert_eq!(t.server_name.as_deref(), Some("host.com"));
            assert_eq!(t.insecure, Some(true));
        }
        _ => panic!("Expected Tuic"),
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

// ── Subscription URL parsers (ssr/snell/socks5/ssh) ─────────────────────

#[test]
fn test_parse_ssr_url() {
    use proxy_convert::protocols::subscription::parse_proxy_url;
    // body = "1.2.3.4:443:auth_aes128_md5:aes-256-cfb:plain:base64(mypass)/?remarks=base64(mynode)"
    let url = "ssr://MS4yLjMuNDo0NDM6YXV0aF9hZXMxMjhfbWQ1OmFlcy0yNTYtY2ZiOnBsYWluOmJYbHdZWE56Lz9yZW1hcmtzPWJYbHViMlJs";
    let s = parse_proxy_url(url).unwrap().expect("parsed ssr");
    assert_eq!(s.protocol, "ssr");
    assert_eq!(s.server, "1.2.3.4");
    assert_eq!(s.port, 443);
    assert_eq!(s.method.as_deref(), Some("aes-256-cfb"));
    assert_eq!(s.password.as_deref(), Some("mypass"));
    assert_eq!(s.name, "mynode");
    match &s.params {
        ProxyParams::Generic { extras } => {
            assert_eq!(
                extras.get("protocol").and_then(|v| v.as_str()),
                Some("auth_aes128_md5")
            );
            assert_eq!(extras.get("obfs").and_then(|v| v.as_str()), Some("plain"));
        }
        _ => panic!("Expected Generic"),
    }
}

#[test]
fn test_parse_snell_url() {
    use proxy_convert::protocols::subscription::parse_proxy_url;
    let s = parse_proxy_url("snell://yourpsk@example.com:443?obfs=tls&obfs-host=cdn.example.com&version=3#snell-1")
        .unwrap()
        .expect("parsed snell");
    assert_eq!(s.protocol, "snell");
    assert_eq!(s.server, "example.com");
    assert_eq!(s.port, 443);
    assert_eq!(s.password.as_deref(), Some("yourpsk"));
    assert_eq!(s.name, "snell-1");
    match &s.params {
        ProxyParams::Generic { extras } => {
            assert_eq!(extras.get("version").and_then(|v| v.as_u64()), Some(3));
            let obfs_opts = extras.get("obfs-opts").and_then(|v| v.as_object()).unwrap();
            assert_eq!(obfs_opts.get("mode").and_then(|v| v.as_str()), Some("tls"));
            assert_eq!(
                obfs_opts.get("host").and_then(|v| v.as_str()),
                Some("cdn.example.com")
            );
        }
        _ => panic!("Expected Generic"),
    }
}

#[test]
fn test_parse_socks5_url() {
    use proxy_convert::protocols::subscription::parse_proxy_url;
    let s = parse_proxy_url("socks5://alice:secret@example.com:1080?tls=1&allowInsecure=1#socks-1")
        .unwrap()
        .expect("parsed socks5");
    assert_eq!(s.protocol, "socks5");
    assert_eq!(s.server, "example.com");
    assert_eq!(s.port, 1080);
    assert_eq!(s.password.as_deref(), Some("secret"));
    assert_eq!(s.name, "socks-1");
    match &s.params {
        ProxyParams::Generic { extras } => {
            assert_eq!(extras.get("username").and_then(|v| v.as_str()), Some("alice"));
            assert_eq!(extras.get("tls").and_then(|v| v.as_bool()), Some(true));
            assert_eq!(
                extras.get("skip-cert-verify").and_then(|v| v.as_bool()),
                Some(true)
            );
        }
        _ => panic!("Expected Generic"),
    }

    // Default port 1080 when port omitted, no userinfo.
    let s2 = parse_proxy_url("socks5://example.com#anon").unwrap().expect("parsed socks5 anon");
    assert_eq!(s2.port, 1080);
    assert!(s2.password.is_none());
}

#[test]
fn test_parse_ssh_url() {
    use proxy_convert::protocols::subscription::parse_proxy_url;
    let s = parse_proxy_url("ssh://root:hunter2@example.com:2222#bastion")
        .unwrap()
        .expect("parsed ssh");
    assert_eq!(s.protocol, "ssh");
    assert_eq!(s.server, "example.com");
    assert_eq!(s.port, 2222);
    assert_eq!(s.password.as_deref(), Some("hunter2"));
    assert_eq!(s.name, "bastion");
    match &s.params {
        ProxyParams::Generic { extras } => {
            assert_eq!(extras.get("user").and_then(|v| v.as_str()), Some("root"));
        }
        _ => panic!("Expected Generic"),
    }

    // Default port 22 + no password.
    let s2 = parse_proxy_url("ssh://root@example.com").unwrap().expect("parsed ssh no port");
    assert_eq!(s2.port, 22);
    assert!(s2.password.is_none());
}

#[test]
fn test_parse_subscription_with_ssr_lines() {
    // Regression: detect.rs accepts ssr:// as subscription, but parse_proxy_url
    // used to drop it → the whole sub returned 0 nodes. Now ssr lines yield ProxyServer.
    use proxy_convert::protocols::subscription::parse_subscription;
    let content = concat!(
        "ssr://MS4yLjMuNDo0NDM6YXV0aF9hZXMxMjhfbWQ1OmFlcy0yNTYtY2ZiOnBsYWluOmJYbHdZWE56Lz9yZW1hcmtzPWJYbHViMlJs\n",
        "ss://YWVzLTI1Ni1nY206cGFzcw==@5.6.7.8:8388#ss-node\n"
    );
    let servers = parse_subscription(content).unwrap();
    assert_eq!(servers.len(), 2);
    assert_eq!(servers[0].protocol, "ssr");
    assert_eq!(servers[1].protocol, "shadowsocks");
}

// ── Clash typed extract: ssr / socks5 / http / snell ────────────────────

#[test]
fn test_extract_clash_ssr() {
    let config: clash::Config = serde_json::from_value(serde_json::json!({
        "proxies": [{
            "name": "ssr-1",
            "type": "ssr",
            "server": "1.2.3.4",
            "port": 443,
            "cipher": "aes-256-cfb",
            "password": "ssrpass",
            "obfs": "tls1.2_ticket_auth",
            "protocol": "auth_aes128_md5",
            "obfs-param": "cloudfront.net",
            "protocol-param": "12345:abcdef",
            "udp": true
        }]
    }))
    .unwrap();
    let source = make_source(Config::Clash(config), Protocol::Clash);
    let servers = source.extract_servers().unwrap();
    assert_eq!(servers.len(), 1);
    let s = &servers[0];
    assert_eq!(s.protocol, "ssr");
    assert_eq!(s.password.as_deref(), Some("ssrpass"));
    assert_eq!(s.method.as_deref(), Some("aes-256-cfb"));
    match &s.params {
        ProxyParams::ShadowsocksR {
            cipher,
            protocol,
            obfs,
            obfs_param,
            protocol_param,
            udp,
            ..
        } => {
            assert_eq!(cipher, "aes-256-cfb");
            assert_eq!(protocol, "auth_aes128_md5");
            assert_eq!(obfs, "tls1.2_ticket_auth");
            assert_eq!(obfs_param.as_deref(), Some("cloudfront.net"));
            assert_eq!(protocol_param.as_deref(), Some("12345:abcdef"));
            assert_eq!(*udp, Some(true));
        }
        _ => panic!("Expected ShadowsocksR, got {:?}", s.params),
    }
}

#[test]
fn test_extract_clash_socks5() {
    let config: clash::Config = serde_json::from_value(serde_json::json!({
        "proxies": [{
            "name": "socks-1",
            "type": "socks5",
            "server": "1.2.3.4",
            "port": 1080,
            "username": "alice",
            "password": "secret",
            "tls": true,
            "skip-cert-verify": true,
            "udp": true
        }]
    }))
    .unwrap();
    let source = make_source(Config::Clash(config), Protocol::Clash);
    let servers = source.extract_servers().unwrap();
    assert_eq!(servers.len(), 1);
    let s = &servers[0];
    assert_eq!(s.protocol, "socks5");
    assert_eq!(s.password.as_deref(), Some("secret"));
    match &s.params {
        ProxyParams::Socks {
            version,
            username,
            tls,
            udp,
            ..
        } => {
            assert_eq!(version.as_deref(), Some("5"));
            assert_eq!(username.as_deref(), Some("alice"));
            let tls = tls.as_ref().expect("tls");
            assert!(tls.enabled);
            assert_eq!(tls.insecure, Some(true));
            assert_eq!(*udp, Some(true));
        }
        _ => panic!("Expected Socks"),
    }
}

#[test]
fn test_extract_clash_http() {
    let config: clash::Config = serde_json::from_value(serde_json::json!({
        "proxies": [{
            "name": "http-1",
            "type": "http",
            "server": "1.2.3.4",
            "port": 8080,
            "username": "admin",
            "password": "admin"
        }]
    }))
    .unwrap();
    let source = make_source(Config::Clash(config), Protocol::Clash);
    let servers = source.extract_servers().unwrap();
    assert_eq!(servers.len(), 1);
    let s = &servers[0];
    assert_eq!(s.protocol, "http");
    assert_eq!(s.password.as_deref(), Some("admin"));
    match &s.params {
        ProxyParams::Http { username, .. } => {
            assert_eq!(username.as_deref(), Some("admin"));
        }
        _ => panic!("Expected Http"),
    }
}

#[test]
fn test_extract_clash_snell() {
    let config: clash::Config = serde_json::from_value(serde_json::json!({
        "proxies": [{
            "name": "snell-1",
            "type": "snell",
            "server": "1.2.3.4",
            "port": 443,
            "psk": "yourpsk",
            "version": 3,
            "obfs-opts": {
                "mode": "tls",
                "host": "cdn.example.com"
            }
        }]
    }))
    .unwrap();
    let source = make_source(Config::Clash(config), Protocol::Clash);
    let servers = source.extract_servers().unwrap();
    assert_eq!(servers.len(), 1);
    let s = &servers[0];
    assert_eq!(s.protocol, "snell");
    match &s.params {
        ProxyParams::Snell {
            psk,
            version,
            obfs_opts,
            ..
        } => {
            assert_eq!(psk, "yourpsk");
            assert_eq!(*version, Some(3));
            let obfs = obfs_opts.as_ref().and_then(|v| v.as_object()).unwrap();
            assert_eq!(obfs.get("mode").and_then(|v| v.as_str()), Some("tls"));
            assert_eq!(
                obfs.get("host").and_then(|v| v.as_str()),
                Some("cdn.example.com")
            );
        }
        _ => panic!("Expected Snell"),
    }
}
