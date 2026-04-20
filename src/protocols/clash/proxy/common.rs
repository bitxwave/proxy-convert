use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;
use std::collections::HashMap;

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(untagged)]
pub enum HttpHeader {
    Str(String),
    Arr(Vec<String>),
}

#[skip_serializing_none]
#[derive(Default, Serialize, Deserialize, Debug, Clone)]
pub struct GrpcOpts {
    #[serde(rename = "grpc-service-name")]
    pub grpc_service_name: Option<String>,
}

#[skip_serializing_none]
#[derive(Default, Serialize, Deserialize, Debug, Clone)]
pub struct WsOpts {
    pub path: Option<String>,
    pub headers: Option<HashMap<String, HttpHeader>>,
    #[serde(rename = "max-early-data")]
    pub max_early_data: Option<usize>,
    #[serde(rename = "early-data-header-name")]
    pub early_data_header_name: Option<String>,
}

#[skip_serializing_none]
#[derive(Default, Serialize, Deserialize, Debug, Clone)]
pub struct H2Opts {
    pub path: Option<String>,
    pub host: Option<Vec<String>>,
}

#[skip_serializing_none]
#[derive(Default, Serialize, Deserialize, Debug, Clone)]
pub struct HttpOpts {
    pub method: Option<String>,
    pub path: Option<Vec<String>>,
    pub headers: Option<HashMap<String, HttpHeader>>,
}
