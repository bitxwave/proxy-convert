//! Integration tests for URL-based source fetching using wiremock.
//!
//! Covers the scenarios that historically caused production issues:
//! - panels that filter by User-Agent (403 without the right UA)
//! - retry behavior on transient 5xx
//! - error classification / message hints

use proxy_convert::commands::convert::ConvertCommand;
use proxy_convert::core::config::AppConfig;
use proxy_convert::core::error::{ConvertError, NetworkErrorKind};
use proxy_convert::protocols::ProtocolRegistry;
use proxy_convert::utils::source::SourceLoader;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn config_with(timeout: u64, retries: u32) -> AppConfig {
    AppConfig {
        timeout_seconds: timeout,
        retry_count: retries,
        ..AppConfig::default()
    }
}

fn minimal_singbox_body() -> &'static str {
    r#"{
        "inbounds": [],
        "outbounds": [
            {"type": "direct", "tag": "direct"},
            {"type": "shadowsocks", "tag": "ss1", "server": "1.1.1.1", "server_port": 443, "method": "aes-256-gcm", "password": "secret"}
        ]
    }"#
}

#[tokio::test]
async fn fetches_http_subscription_successfully() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/sub"))
        .respond_with(ResponseTemplate::new(200).set_body_string(minimal_singbox_body()))
        .mount(&server)
        .await;

    let source_str = format!("{}/sub?type=singbox", server.uri());
    let meta = ConvertCommand::parse_source_string(&source_str).unwrap();
    let registry = ProtocolRegistry::init();
    let config = config_with(5, 0);

    let source = SourceLoader::load_source(&meta, &registry, &config).await.unwrap();
    let servers = source.extract_servers().unwrap();
    assert!(servers.iter().any(|s| s.protocol == "shadowsocks"));
}

#[tokio::test]
async fn status_403_reports_as_status_kind() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/blocked"))
        .respond_with(ResponseTemplate::new(403))
        .mount(&server)
        .await;

    let source_str = format!("{}/blocked?type=singbox", server.uri());
    let meta = ConvertCommand::parse_source_string(&source_str).unwrap();
    let registry = ProtocolRegistry::init();
    let config = config_with(5, 0);

    let err = SourceLoader::load_source(&meta, &registry, &config)
        .await
        .expect_err("403 should error");

    match err {
        ConvertError::NetworkError { kind, .. } => {
            assert_eq!(kind, NetworkErrorKind::Status(403));
        }
        other => panic!("expected NetworkError, got {:?}", other),
    }
}

#[tokio::test]
async fn retries_transient_5xx_then_succeeds() {
    let server = MockServer::start().await;
    // First call → 503, second call → 200. `expect` bounds ensure both are hit.
    Mock::given(method("GET"))
        .and(path("/sub"))
        .respond_with(ResponseTemplate::new(503))
        .up_to_n_times(1)
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/sub"))
        .respond_with(ResponseTemplate::new(200).set_body_string(minimal_singbox_body()))
        .expect(1)
        .mount(&server)
        .await;

    let source_str = format!("{}/sub?type=singbox", server.uri());
    let meta = ConvertCommand::parse_source_string(&source_str).unwrap();
    let registry = ProtocolRegistry::init();
    // 1 retry is enough — first attempt hits the 503 mock, retry hits the 200.
    let config = config_with(5, 1);

    let source = SourceLoader::load_source(&meta, &registry, &config)
        .await
        .expect("retry should succeed on second try");
    assert!(!source.extract_servers().unwrap().is_empty());
}

#[tokio::test]
async fn does_not_retry_client_errors() {
    let server = MockServer::start().await;
    // 404 is permanent — even with retries=3, we should only see 1 request.
    Mock::given(method("GET"))
        .and(path("/missing"))
        .respond_with(ResponseTemplate::new(404))
        .expect(1)
        .mount(&server)
        .await;

    let source_str = format!("{}/missing?type=singbox", server.uri());
    let meta = ConvertCommand::parse_source_string(&source_str).unwrap();
    let registry = ProtocolRegistry::init();
    let config = config_with(5, 3);

    let err = SourceLoader::load_source(&meta, &registry, &config)
        .await
        .expect_err("404 should error");
    match err {
        ConvertError::NetworkError { kind: NetworkErrorKind::Status(404), .. } => {}
        other => panic!("expected Status(404), got {:?}", other),
    }
    // Mock's `expect(1)` is verified on drop — wiremock will panic if hit count differs.
}
