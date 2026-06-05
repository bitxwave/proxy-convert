use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;

/// Clash (mihomo) Hysteria2 proxy. See https://wiki.metacubex.one/config/proxies/hysteria2/
#[skip_serializing_none]
#[derive(Default, Serialize, Deserialize, Debug, Clone)]
pub struct Hysteria2 {
    pub name: String,
    #[serde(rename = "interface-name")]
    pub interface_name: Option<String>,
    #[serde(rename = "routing-mark")]
    pub routing_mark: Option<usize>,
    pub server: String,
    pub port: u16,
    /// Port-hopping range. Accepts strings like "443-8443" or "1000,2000-3000".
    pub ports: Option<String>,
    /// Hop interval in seconds — accepts integer or "15-30" range.
    #[serde(rename = "hop-interval")]
    pub hop_interval: Option<serde_json::Value>,
    pub password: String,
    /// Up bandwidth — accepts "30 Mbps" string or raw number (Mbps).
    pub up: Option<serde_json::Value>,
    /// Down bandwidth — same shape as `up`.
    pub down: Option<serde_json::Value>,
    /// Currently only "salamander" is supported, empty disables.
    pub obfs: Option<String>,
    #[serde(rename = "obfs-password")]
    pub obfs_password: Option<String>,
    pub sni: Option<String>,
    #[serde(rename = "skip-cert-verify")]
    pub skip_cert_verify: Option<bool>,
    pub fingerprint: Option<String>,
    #[serde(default)]
    pub alpn: Vec<String>,
    pub udp: Option<bool>,
}
