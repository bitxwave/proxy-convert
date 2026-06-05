use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;

/// Clash (mihomo) Hysteria v1 proxy. See https://wiki.metacubex.one/config/proxies/hysteria/
#[skip_serializing_none]
#[derive(Default, Serialize, Deserialize, Debug, Clone)]
pub struct Hysteria {
    pub name: String,
    #[serde(rename = "interface-name")]
    pub interface_name: Option<String>,
    #[serde(rename = "routing-mark")]
    pub routing_mark: Option<usize>,
    pub server: String,
    pub port: u16,
    /// Optional port hopping list, e.g. "1000,2000-3000,4000".
    pub ports: Option<String>,
    /// Authentication password — Hysteria v1 uses `auth-str` instead of `password`.
    #[serde(rename = "auth-str")]
    pub auth_str: Option<String>,
    pub up: serde_json::Value,
    pub down: serde_json::Value,
    pub obfs: Option<String>,
    #[serde(default)]
    pub alpn: Vec<String>,
    /// Transport variant: "udp" / "wechat-video" / "faketcp"
    pub protocol: Option<String>,
    pub sni: Option<String>,
    #[serde(rename = "skip-cert-verify")]
    pub skip_cert_verify: Option<bool>,
    #[serde(rename = "recv-window-conn")]
    pub recv_window_conn: Option<u32>,
    #[serde(rename = "recv-window")]
    pub recv_window: Option<u32>,
    pub disable_mtu_discovery: Option<bool>,
    pub fingerprint: Option<String>,
    #[serde(rename = "fast-open")]
    pub fast_open: Option<bool>,
    pub udp: Option<bool>,
}
