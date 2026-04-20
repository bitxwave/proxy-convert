use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;

use super::common::{GrpcOpts, H2Opts, HttpOpts, WsOpts};

#[skip_serializing_none]
#[derive(Default, Serialize, Deserialize, Debug, Clone)]
pub struct Vmess {
    pub name: String,
    #[serde(rename = "interface-name")]
    pub interface_name: Option<String>,
    #[serde(rename = "routing-mark")]
    pub routing_mark: Option<usize>,
    pub server: String,
    pub port: u16,
    pub uuid: Option<String>,
    #[serde(rename = "alterId")]
    pub alter_id: Option<usize>,
    pub cipher: Option<String>,
    pub udp: Option<bool>,
    pub tls: Option<bool>,
    #[serde(rename = "skip-cert-verify")]
    pub skip_cert_verify: Option<bool>,
    pub servername: Option<String>,
    pub network: Option<String>,
    #[serde(rename = "http-opts")]
    pub http_opts: Option<HttpOpts>,
    #[serde(rename = "h2-opts")]
    pub h2_opts: Option<H2Opts>,
    #[serde(rename = "grpc-opts")]
    pub grpc_opts: Option<GrpcOpts>,
    #[serde(rename = "ws-opts")]
    pub ws_opts: Option<WsOpts>,
}
