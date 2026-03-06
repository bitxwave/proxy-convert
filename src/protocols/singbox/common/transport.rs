use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;
use indexmap::IndexMap;

#[skip_serializing_none]
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum Transport {
    HTTP(HTTP),
    WS(WS),
    Quic(Quic),
    GRPC(GRPC),
    HttpUpgrade(HttpUpgrade),
}

#[skip_serializing_none]
#[derive(Default, Serialize, Deserialize, Debug, Clone)]
pub struct HTTP {
    host: Option<Vec<String>>,
    path: Option<String>,
    method: Option<String>,
    headers: Option<IndexMap<String, String>>,
    idle_timeout: Option<String>,
    ping_timeout: Option<String>,
}

#[skip_serializing_none]
#[derive(Default, Serialize, Deserialize, Debug, Clone)]
pub struct WS {
    path: Option<String>,
    headers: Option<IndexMap<String, String>>,
    max_early_data: Option<usize>,
    early_data_header_name: Option<String>,
}

#[skip_serializing_none]
#[derive(Default, Serialize, Deserialize, Debug, Clone)]
pub struct Quic {}

#[skip_serializing_none]
#[derive(Default, Serialize, Deserialize, Debug, Clone)]
pub struct GRPC {
    service_name: Option<String>,
    idle_timeout: Option<String>,
    ping_timeout: Option<String>,
    permit_without_stream: Option<bool>,
}

#[skip_serializing_none]
#[derive(Default, Serialize, Deserialize, Debug, Clone)]
pub struct HttpUpgrade {
    host: Option<String>,
    path: Option<String>,
    headers: Option<IndexMap<String, String>>,
}
