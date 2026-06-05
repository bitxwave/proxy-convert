use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;

use super::common::{GrpcOpts, H2Opts, HttpOpts, WsOpts};

/// Clash (mihomo) VLESS proxy. See https://wiki.metacubex.one/config/proxies/vless/
#[skip_serializing_none]
#[derive(Default, Serialize, Deserialize, Debug, Clone)]
pub struct Vless {
    pub name: String,
    #[serde(rename = "interface-name")]
    pub interface_name: Option<String>,
    #[serde(rename = "routing-mark")]
    pub routing_mark: Option<usize>,
    pub server: String,
    pub port: u16,
    pub uuid: String,
    pub flow: Option<String>,
    pub udp: Option<bool>,
    /// VLESS encryption parameter — usually empty string in real configs.
    pub encryption: Option<String>,
    #[serde(rename = "packet-encoding")]
    pub packet_encoding: Option<String>,
    pub tls: Option<bool>,
    pub servername: Option<String>,
    #[serde(default)]
    pub alpn: Vec<String>,
    pub fingerprint: Option<String>,
    #[serde(rename = "client-fingerprint")]
    pub client_fingerprint: Option<String>,
    #[serde(rename = "skip-cert-verify")]
    pub skip_cert_verify: Option<bool>,
    #[serde(rename = "reality-opts")]
    pub reality_opts: Option<RealityOpts>,
    pub network: Option<String>,
    #[serde(rename = "ws-opts")]
    pub ws_opts: Option<WsOpts>,
    #[serde(rename = "grpc-opts")]
    pub grpc_opts: Option<GrpcOpts>,
    #[serde(rename = "h2-opts")]
    pub h2_opts: Option<H2Opts>,
    #[serde(rename = "http-opts")]
    pub http_opts: Option<HttpOpts>,
}

#[skip_serializing_none]
#[derive(Default, Serialize, Deserialize, Debug, Clone)]
pub struct RealityOpts {
    #[serde(rename = "public-key")]
    pub public_key: Option<String>,
    #[serde(rename = "short-id")]
    pub short_id: Option<String>,
}
