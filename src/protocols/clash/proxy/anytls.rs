use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;

/// Clash (mihomo) AnyTLS proxy. See https://wiki.metacubex.one/config/proxies/anytls/
#[skip_serializing_none]
#[derive(Default, Serialize, Deserialize, Debug, Clone)]
pub struct AnyTls {
    pub name: String,
    #[serde(rename = "interface-name")]
    pub interface_name: Option<String>,
    #[serde(rename = "routing-mark")]
    pub routing_mark: Option<usize>,
    pub server: String,
    pub port: u16,
    pub password: String,
    pub udp: Option<bool>,
    pub sni: Option<String>,
    #[serde(default)]
    pub alpn: Vec<String>,
    #[serde(rename = "skip-cert-verify")]
    pub skip_cert_verify: Option<bool>,
    #[serde(rename = "client-fingerprint")]
    pub client_fingerprint: Option<String>,
    /// Idle session check interval, accepts integer seconds (mihomo) or duration string.
    #[serde(rename = "idle-session-check-interval")]
    pub idle_session_check_interval: Option<serde_json::Value>,
    /// Idle session timeout, accepts integer seconds (mihomo) or duration string.
    #[serde(rename = "idle-session-timeout")]
    pub idle_session_timeout: Option<serde_json::Value>,
    #[serde(rename = "min-idle-session")]
    pub min_idle_session: Option<u32>,
}
