use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;

/// Clash (mihomo) TUIC proxy. v5 uses uuid+password, v4 uses token only.
/// See https://wiki.metacubex.one/config/proxies/tuic/
#[skip_serializing_none]
#[derive(Default, Serialize, Deserialize, Debug, Clone)]
pub struct Tuic {
    pub name: String,
    #[serde(rename = "interface-name")]
    pub interface_name: Option<String>,
    #[serde(rename = "routing-mark")]
    pub routing_mark: Option<usize>,
    pub server: String,
    pub port: u16,
    /// TUIC v4 only — mutually exclusive with uuid/password.
    pub token: Option<String>,
    /// TUIC v5: user UUID.
    pub uuid: Option<String>,
    /// TUIC v5: user password.
    pub password: Option<String>,
    pub ip: Option<String>,
    #[serde(rename = "heartbeat-interval")]
    pub heartbeat_interval: Option<u32>,
    #[serde(rename = "disable-sni")]
    pub disable_sni: Option<bool>,
    #[serde(rename = "reduce-rtt")]
    pub reduce_rtt: Option<bool>,
    #[serde(rename = "request-timeout")]
    pub request_timeout: Option<u32>,
    #[serde(rename = "udp-relay-mode")]
    pub udp_relay_mode: Option<String>,
    #[serde(rename = "congestion-controller")]
    pub congestion_controller: Option<String>,
    #[serde(rename = "max-udp-relay-packet-size")]
    pub max_udp_relay_packet_size: Option<u32>,
    #[serde(rename = "fast-open")]
    pub fast_open: Option<bool>,
    #[serde(rename = "max-open-streams")]
    pub max_open_streams: Option<u32>,
    pub cwnd: Option<u32>,
    pub sni: Option<String>,
    #[serde(default)]
    pub alpn: Vec<String>,
    #[serde(rename = "skip-cert-verify")]
    pub skip_cert_verify: Option<bool>,
    pub fingerprint: Option<String>,
    #[serde(rename = "client-fingerprint")]
    pub client_fingerprint: Option<String>,
    #[serde(rename = "ca-str")]
    pub ca_str: Option<String>,
    pub ca: Option<String>,
    pub udp: Option<bool>,
}
