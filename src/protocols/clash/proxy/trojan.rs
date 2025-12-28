use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;
use std::collections::HashMap;

#[skip_serializing_none]
#[derive(Default, Serialize, Deserialize, Debug)]
pub struct Trojan {
    pub name: String,
    #[serde(rename = "interface-name")]
    pub interface_name: Option<String>,
    #[serde(rename = "routing-mark")]
    pub routing_mark: Option<usize>,
    pub server: String,
    pub port: u16,
    pub password: Option<String>,
    pub network: Option<String>,
    pub udp: Option<bool>,
    pub sni: Option<String>,
    pub alpn: Vec<String>,
    #[serde(rename = "skip-cert-verify")]
    pub skip_cert_verify: Option<bool>,
    #[serde(rename = "grpc-opts")]
    pub grpc_opts: Option<GrpcOpts>,
    #[serde(rename = "ws_opts")]
    pub ws_opts: Option<WsOpts>,
}

#[skip_serializing_none]
#[derive(Default, Serialize, Deserialize, Debug)]
pub struct GrpcOpts {
    #[serde(rename = "grpc-service-name")]
    pub grpc_service_name: Option<String>,
}

#[skip_serializing_none]
#[derive(Default, Serialize, Deserialize, Debug)]
pub struct WsOpts {
    pub path: Option<String>,
    pub headers: Option<HashMap<String, HttpHeader>>,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(untagged)]
pub enum HttpHeader {
    Str(String),
    Arr(Vec<String>),
}
