//! Integration tests: full convert/validate flow with file-based sources.

use proxy_convert::commands::convert::{ConvertCommand, OutputProtocol};
use proxy_convert::core::config::AppConfig;
use proxy_convert::core::source::SourceProtocol;
use proxy_convert::protocols::ProtocolRegistry;
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
    assert!(matches!(source_meta.source_type, SourceProtocol::SingBox));

    let source = proxy_convert::utils::source::SourceLoader::load_source(
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
        &OutputProtocol::SingBox,
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
        &OutputProtocol::SingBox,
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
    let servers = proxy_convert::protocols::subscription::parse_plain_text(content).unwrap();
    assert_eq!(servers.len(), 2);
    assert_eq!(servers[0].protocol, "vmess");
    assert_eq!(servers[0].name, "name1");
    assert_eq!(servers[1].protocol, "trojan");
    assert_eq!(servers[1].name, "name2");
}
