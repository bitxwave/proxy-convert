//! Integration tests: full convert/validate flow with file-based sources.

use subforge::commands::convert::ConvertCommand;
use subforge::core::config::AppConfig;
use subforge::core::source::Protocol;
use subforge::protocols::ProtocolRegistry;
use tempfile::NamedTempFile;

fn minimal_singbox_content() -> &'static str {
    r#"{
        "inbounds": [],
        "outbounds": [
            {"type": "direct", "tag": "direct"},
            {"type": "shadowsocks", "tag": "ss1", "server": "1.1.1.1", "server_port": 443, "method": "aes-256-gcm", "password": "secret"}
        ]
    }"#
}

fn minimal_clash_content() -> &'static str {
    r#"port: 7890
proxies:
  - name: node1
    type: ss
    server: 2.2.2.2
    port: 443
    cipher: aes-256-gcm
    password: pwd
"#
}

#[tokio::test]
async fn integration_convert_file_source_singbox_to_json() {
    let registry = ProtocolRegistry::init();
    let config = AppConfig::default();

    let file = NamedTempFile::new().unwrap();
    let path = file.path().to_string_lossy();
    std::fs::write(file.path(), minimal_singbox_content()).unwrap();

    let source_str = format!("{}?type=singbox", path);
    let source_meta = ConvertCommand::parse_source_string(&source_str).unwrap();
    assert!(matches!(source_meta.source_type, Protocol::SingBox));

    let source = subforge::utils::source::SourceLoader::load_source(
        &source_meta,
        &registry,
        &config,
    )
    .await
    .unwrap();

    let servers = source.extract_servers().unwrap();
    assert!(!servers.is_empty());
    assert!(servers.iter().any(|s| s.protocol == "shadowsocks"));

    let out_dir = tempfile::tempdir().unwrap();
    let output_path = out_dir.path().join("config.json");
    let result = ConvertCommand::start_convert(
        &[source_meta],
        None,
        &Protocol::SingBox,
        Some(output_path.to_str().unwrap()),
        None,
        &registry,
        &config,
    )
    .await;

    assert!(result.is_ok(), "convert failed: {:?}", result.err());
    assert!(output_path.exists());
    let content = std::fs::read_to_string(&output_path).unwrap();
    assert!(content.contains("outbounds"));
    assert!(content.contains("shadowsocks") || content.contains("ss1"));
}

#[tokio::test]
async fn integration_convert_file_source_clash_to_singbox() {
    let registry = ProtocolRegistry::init();
    let config = AppConfig::default();

    let file = NamedTempFile::new().unwrap();
    let path = file.path().to_string_lossy();
    std::fs::write(file.path(), minimal_clash_content()).unwrap();

    let source_str = format!("{}?type=clash", path);
    let source_meta = ConvertCommand::parse_source_string(&source_str).unwrap();

    let out_dir = tempfile::tempdir().unwrap();
    let output_path = out_dir.path().join("out.json");
    let result = ConvertCommand::start_convert(
        &[source_meta],
        None,
        &Protocol::SingBox,
        Some(output_path.to_str().unwrap()),
        None,
        &registry,
        &config,
    )
    .await;

    assert!(result.is_ok(), "convert failed: {:?}", result.err());
    assert!(output_path.exists());
    let content = std::fs::read_to_string(&output_path).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&content).unwrap();
    assert!(parsed.get("outbounds").is_some());
}

#[test]
fn integration_subscription_parse_plain_text() {
    let content = "vmess://uuid@host:443#name1\ntrojan://pwd@h2:8443#name2\n";
    let servers = subforge::protocols::subscription::parse_plain_text(content).unwrap();
    assert_eq!(servers.len(), 2);
    assert_eq!(servers[0].protocol, "vmess");
    assert_eq!(servers[0].name, "name1");
    assert_eq!(servers[1].protocol, "trojan");
    assert_eq!(servers[1].name, "name2");
}

#[test]
fn integration_subscription_parse_mixed_with_new_protocols() {
    // Locks in the protocol-coverage work end-to-end: a subscription mixing
    // ss/ssr/snell/socks5/ssh/hysteria/tuic produces one node per line, none
    // dropped (the bug pre-PR was that ssr lines were detected as "subscription"
    // and then silently skipped).
    let content = concat!(
        "ss://YWVzLTI1Ni1nY206cGFzcw==@1.1.1.1:8388#ss-node\n",
        "ssr://MS4yLjMuNDo0NDM6YXV0aF9hZXMxMjhfbWQ1OmFlcy0yNTYtY2ZiOnBsYWluOmJYbHdZWE56Lz9yZW1hcmtzPWJYbHViMlJs\n",
        "snell://yourpsk@2.2.2.2:443?obfs=tls&obfs-host=cdn.example.com&version=3#snell-1\n",
        "socks5://alice:secret@3.3.3.3:1080#socks-1\n",
        "ssh://root:hunter2@4.4.4.4:22#ssh-1\n",
    );
    let servers = subforge::protocols::subscription::parse_plain_text(content).unwrap();
    let protocols: Vec<&str> = servers.iter().map(|s| s.protocol.as_str()).collect();
    assert_eq!(
        protocols,
        vec!["shadowsocks", "ssr", "snell", "socks5", "ssh"]
    );
}

#[tokio::test]
async fn integration_clash_socks5_to_singbox_emits_socks_with_nested_tls() {
    // End-to-end via ConvertCommand: a Clash YAML with a socks5 node containing
    // tls:true + skip-cert-verify gets converted to sing-box JSON, the type is
    // renamed to `socks`, and the flat tls boolean is rebuilt as a nested
    // tls object. This is the real-world bug fix landed in the previous commit;
    // probing it through start_convert (not just create_node_config) confirms
    // the typed path survives the full pipeline.
    let registry = ProtocolRegistry::init();
    let config = AppConfig::default();

    let clash_yaml = r#"port: 7890
proxies:
  - name: socks-node
    type: socks5
    server: 1.2.3.4
    port: 1080
    username: alice
    password: secret
    tls: true
    skip-cert-verify: true
    udp: true
"#;

    let file = NamedTempFile::new().unwrap();
    let path = file.path().to_string_lossy();
    std::fs::write(file.path(), clash_yaml).unwrap();

    let source_str = format!("{}?type=clash", path);
    let source_meta = ConvertCommand::parse_source_string(&source_str).unwrap();

    let out_dir = tempfile::tempdir().unwrap();
    let output_path = out_dir.path().join("out.json");
    let result = ConvertCommand::start_convert(
        &[source_meta],
        None,
        &Protocol::SingBox,
        Some(output_path.to_str().unwrap()),
        None,
        &registry,
        &config,
    )
    .await;
    assert!(result.is_ok(), "convert failed: {:?}", result.err());

    let content = std::fs::read_to_string(&output_path).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&content).unwrap();
    let outbounds = parsed["outbounds"].as_array().expect("outbounds array");
    let socks_node = outbounds
        .iter()
        .find(|o| o["tag"] == "socks-node")
        .expect("socks-node not in outbounds");

    assert_eq!(
        socks_node["type"], "socks",
        "type should be renamed socks5 → socks; got {}",
        socks_node
    );
    assert_eq!(socks_node["server"], "1.2.3.4");
    assert_eq!(socks_node["server_port"], 1080);
    assert_eq!(socks_node["username"], "alice");
    assert_eq!(socks_node["password"], "secret");
    // Nested TLS object, not flat boolean.
    assert_eq!(socks_node["tls"]["enabled"], true);
    assert_eq!(socks_node["tls"]["insecure"], true);
    assert!(
        socks_node.get("skip-cert-verify").is_none(),
        "stray skip-cert-verify in: {}",
        socks_node
    );
}
