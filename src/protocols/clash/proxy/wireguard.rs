use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;

/// Clash (mihomo) WireGuard proxy. See https://wiki.metacubex.one/config/proxies/wg/
///
/// mihomo accepts two YAML shapes:
///   1. simplified — top-level `server` / `port` / `public-key` / `allowed-ips` /
///      `pre-shared-key` / `reserved` for a single peer.
///   2. full — `peers:` list, with `private-key` still at the top level.
///
/// We accept both; the converter expands shape (1) to a single-peer list when
/// emitting sing-box.
#[skip_serializing_none]
#[derive(Default, Serialize, Deserialize, Debug, Clone)]
pub struct WireGuard {
    pub name: String,
    #[serde(rename = "interface-name")]
    pub interface_name: Option<String>,
    #[serde(rename = "routing-mark")]
    pub routing_mark: Option<usize>,
    /// Top-level server (simplified single-peer form).
    pub server: Option<String>,
    pub port: Option<u16>,
    pub ip: Option<String>,
    pub ipv6: Option<String>,
    #[serde(rename = "private-key")]
    pub private_key: String,
    /// Top-level peer fields (simplified form).
    #[serde(rename = "public-key")]
    pub public_key: Option<String>,
    #[serde(rename = "pre-shared-key")]
    pub pre_shared_key: Option<String>,
    #[serde(rename = "allowed-ips", default)]
    pub allowed_ips: Vec<String>,
    /// Reserved bytes — accepts `[209,98,59]` or `"U4An"`.
    pub reserved: Option<serde_json::Value>,
    #[serde(rename = "persistent-keepalive")]
    pub persistent_keepalive: Option<u32>,
    /// Full form — list of peers (overrides simplified top-level peer fields).
    pub peers: Option<Vec<Peer>>,
    pub mtu: Option<u32>,
    pub udp: Option<bool>,
    #[serde(rename = "remote-dns-resolve")]
    pub remote_dns_resolve: Option<bool>,
    #[serde(default)]
    pub dns: Vec<String>,
    #[serde(rename = "dialer-proxy")]
    pub dialer_proxy: Option<String>,
    #[serde(rename = "refresh-server-ip-interval")]
    pub refresh_server_ip_interval: Option<u32>,
}

#[skip_serializing_none]
#[derive(Default, Serialize, Deserialize, Debug, Clone)]
pub struct Peer {
    pub server: String,
    pub port: u16,
    #[serde(rename = "public-key")]
    pub public_key: String,
    #[serde(rename = "pre-shared-key")]
    pub pre_shared_key: Option<String>,
    #[serde(rename = "allowed-ips", default)]
    pub allowed_ips: Vec<String>,
    /// Reserved bytes — accepts list or string.
    pub reserved: Option<serde_json::Value>,
    #[serde(rename = "persistent-keepalive")]
    pub persistent_keepalive: Option<u32>,
}
