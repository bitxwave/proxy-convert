//! Tests for subscription URL parsing (vmess://, vless://, trojan://, ss://, hysteria2://).

use base64::Engine;
use proxy_convert::protocols::subscription;
use proxy_convert::protocols::ProxyParams;

#[test]
fn test_parse_vmess_url() {
    let servers =
        subscription::parse_plain_text("vmess://test-uuid@1.2.3.4:443#MyVmess\n").unwrap();
    assert_eq!(servers.len(), 1);
    assert_eq!(servers[0].name, "MyVmess");
    assert_eq!(servers[0].protocol, "vmess");
    assert_eq!(servers[0].server, "1.2.3.4");
    assert_eq!(servers[0].port, 443);
    match &servers[0].params {
        ProxyParams::Vmess { uuid, .. } => assert_eq!(uuid, "test-uuid"),
        _ => panic!("Expected Vmess params"),
    }
}

#[test]
fn test_parse_trojan_url() {
    let servers =
        subscription::parse_plain_text("trojan://mypassword@5.6.7.8:8443#TrojanNode\n").unwrap();
    assert_eq!(servers.len(), 1);
    assert_eq!(servers[0].name, "TrojanNode");
    assert_eq!(servers[0].protocol, "trojan");
    assert_eq!(servers[0].server, "5.6.7.8");
    assert_eq!(servers[0].port, 8443);
    assert_eq!(servers[0].password.as_deref(), Some("mypassword"));
}

#[test]
fn test_parse_ss_sip002_url() {
    // SIP002 format: ss://base64(method:password)@server:port#name
    let method_pass =
        base64::engine::general_purpose::STANDARD.encode("aes-256-gcm:testpass");
    let url = format!("ss://{}@9.8.7.6:8388#SSNode\n", method_pass);
    let servers = subscription::parse_plain_text(&url).unwrap();
    assert_eq!(servers.len(), 1);
    assert_eq!(servers[0].protocol, "shadowsocks");
    assert_eq!(servers[0].server, "9.8.7.6");
    assert_eq!(servers[0].port, 8388);
    assert_eq!(servers[0].password.as_deref(), Some("testpass"));
    assert_eq!(servers[0].method.as_deref(), Some("aes-256-gcm"));
}

#[test]
fn test_parse_mixed_subscription() {
    let content = "vmess://uuid1@1.1.1.1:443#V1\ntrojan://pass@2.2.2.2:443#T1\n";
    let servers = subscription::parse_plain_text(content).unwrap();
    assert_eq!(servers.len(), 2);
    assert_eq!(servers[0].protocol, "vmess");
    assert_eq!(servers[1].protocol, "trojan");
}

#[test]
fn test_parse_skips_comments_and_blank_lines() {
    let content = "# this is a comment\n\nvmess://uuid@1.1.1.1:443#V1\n\n# another comment\n";
    let servers = subscription::parse_plain_text(content).unwrap();
    assert_eq!(servers.len(), 1);
    assert_eq!(servers[0].name, "V1");
}

#[test]
fn test_parse_unsupported_protocol_returns_empty() {
    let content = "http://not-a-proxy:8080\n";
    let servers = subscription::parse_plain_text(content).unwrap();
    assert_eq!(servers.len(), 0);
}

#[test]
fn test_parse_vmess_preserves_uuid_in_params() {
    let servers =
        subscription::parse_plain_text("vmess://550e8400-e29b-41d4-a716-446655440000@server.com:443#TestNode\n").unwrap();
    assert_eq!(servers.len(), 1);
    match &servers[0].params {
        ProxyParams::Vmess {
            uuid,
            alter_id,
            security,
            tls,
            transport,
        } => {
            assert_eq!(uuid, "550e8400-e29b-41d4-a716-446655440000");
            assert_eq!(*alter_id, None);
            assert_eq!(*security, None);
            assert!(tls.is_none());
            assert!(transport.is_none());
        }
        _ => panic!("Expected Vmess params"),
    }
}

#[test]
fn test_parse_trojan_params_have_no_tls() {
    // URL-parsed trojan has no TLS info embedded
    let servers =
        subscription::parse_plain_text("trojan://secret@host.com:443#TJ\n").unwrap();
    assert_eq!(servers.len(), 1);
    match &servers[0].params {
        ProxyParams::Trojan { tls, transport } => {
            assert!(tls.is_none());
            assert!(transport.is_none());
        }
        _ => panic!("Expected Trojan params"),
    }
}

#[test]
fn test_parse_ss_params_have_cipher() {
    let method_pass =
        base64::engine::general_purpose::STANDARD.encode("chacha20-ietf-poly1305:mypassword");
    let url = format!("ss://{}@10.0.0.1:1080#SSTest\n", method_pass);
    let servers = subscription::parse_plain_text(&url).unwrap();
    assert_eq!(servers.len(), 1);
    match &servers[0].params {
        ProxyParams::Shadowsocks {
            cipher,
            udp,
            plugin,
            plugin_opts,
        } => {
            assert_eq!(cipher, "chacha20-ietf-poly1305");
            assert_eq!(*udp, None);
            assert_eq!(*plugin, None);
            assert_eq!(*plugin_opts, None);
        }
        _ => panic!("Expected Shadowsocks params"),
    }
}

#[test]
fn test_parse_vless_url() {
    let servers = subscription::parse_plain_text(
        "vless://uuid-123@vless.example.com:443?type=ws&security=tls&sni=cdn.example.com&path=%2Fws#MyVless\n",
    )
    .unwrap();
    assert_eq!(servers.len(), 1);
    assert_eq!(servers[0].name, "MyVless");
    assert_eq!(servers[0].protocol, "vless");
    assert_eq!(servers[0].server, "vless.example.com");
    assert_eq!(servers[0].port, 443);
    match &servers[0].params {
        ProxyParams::Vless {
            uuid,
            flow,
            tls,
            transport,
        } => {
            assert_eq!(uuid, "uuid-123");
            assert!(flow.is_none());
            assert!(tls.is_some());
            assert_eq!(
                tls.as_ref().unwrap().server_name.as_deref(),
                Some("cdn.example.com")
            );
            assert!(transport.is_some());
            assert_eq!(transport.as_ref().unwrap().transport_type, "ws");
            assert_eq!(transport.as_ref().unwrap().path.as_deref(), Some("/ws"));
        }
        _ => panic!("Expected Vless params"),
    }
}

#[test]
fn test_parse_vless_url_with_flow() {
    let servers = subscription::parse_plain_text(
        "vless://uuid@server.com:443?flow=xtls-rprx-vision&sni=server.com#VlessVision\n",
    )
    .unwrap();
    assert_eq!(servers.len(), 1);
    match &servers[0].params {
        ProxyParams::Vless { flow, .. } => {
            assert_eq!(flow.as_deref(), Some("xtls-rprx-vision"));
        }
        _ => panic!("Expected Vless params"),
    }
}

#[test]
fn test_parse_hysteria2_url() {
    let servers = subscription::parse_plain_text(
        "hysteria2://mypassword@hy2.example.com:443?sni=hy2.example.com&insecure=1#Hy2Node\n",
    )
    .unwrap();
    assert_eq!(servers.len(), 1);
    assert_eq!(servers[0].name, "Hy2Node");
    assert_eq!(servers[0].protocol, "hysteria2");
    assert_eq!(servers[0].server, "hy2.example.com");
    assert_eq!(servers[0].port, 443);
    assert_eq!(servers[0].password.as_deref(), Some("mypassword"));
    match &servers[0].params {
        ProxyParams::Hysteria2 { tls, obfs_password } => {
            assert!(obfs_password.is_none());
            let tls = tls.as_ref().unwrap();
            assert!(tls.enabled);
            assert_eq!(tls.server_name.as_deref(), Some("hy2.example.com"));
            assert_eq!(tls.insecure, Some(true));
        }
        _ => panic!("Expected Hysteria2 params"),
    }
}

#[test]
fn test_parse_hy2_short_prefix() {
    let servers =
        subscription::parse_plain_text("hy2://pass@server.com:443#Hy2Short\n").unwrap();
    assert_eq!(servers.len(), 1);
    assert_eq!(servers[0].protocol, "hysteria2");
}

#[test]
fn test_parse_base64_subscription() {
    // Simulate a base64-encoded subscription
    let plain = "vmess://uuid@1.1.1.1:443#Node1\ntrojan://pass@2.2.2.2:8443#Node2\n";
    let encoded = base64::engine::general_purpose::STANDARD.encode(plain);
    let servers = subscription::parse_subscription(&encoded).unwrap();
    assert_eq!(servers.len(), 2);
    assert_eq!(servers[0].protocol, "vmess");
    assert_eq!(servers[1].protocol, "trojan");
}
