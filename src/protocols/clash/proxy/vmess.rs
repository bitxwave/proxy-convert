use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;

#[skip_serializing_none]
#[derive(Default, Serialize, Deserialize, Debug)]
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
    pub ws_opts: Option<WSOpts>,
}

#[skip_serializing_none]
#[derive(Default, Serialize, Deserialize, Debug)]
pub struct HttpOpts {
    pub method: Option<String>,
    pub path: Option<Vec<String>>,
    pub headers: Option<HashMap<String, HttpHeader>>,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(untagged)]
pub enum HttpHeader {
    Str(String),
    Arr(Vec<String>),
}

#[skip_serializing_none]
#[derive(Default, Serialize, Deserialize, Debug)]
pub struct H2Opts {
    pub path: Option<String>,
    pub host: Option<Vec<String>>,
}

#[skip_serializing_none]
#[derive(Default, Serialize, Deserialize, Debug)]
pub struct GrpcOpts {
    #[serde(rename = "grpc-service-name")]
    pub grpc_service_name: Option<String>,
}

#[skip_serializing_none]
#[derive(Default, Serialize, Deserialize, Debug)]
pub struct WSOpts {
    pub path: Option<String>,
    pub headers: Option<HashMap<String, HttpHeader>>,
    #[serde(rename = "max-early-data")]
    pub max_early_data: Option<usize>,
    #[serde(rename = "early-data-header-name")]
    pub early_data_header_name: Option<String>,
}
