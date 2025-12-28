use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;

#[skip_serializing_none]
#[derive(Default, Serialize, Deserialize, Debug)]
pub struct ShadowsocksR {
    pub name: String,
    #[serde(rename = "interface-name")]
    pub interface_name: Option<String>,
    #[serde(rename = "routing-mark")]
    pub routing_mark: Option<usize>,
    pub server: String,
    pub port: u16,
    pub cipher: String,
    pub password: String,
    pub obfs: Option<String>,
    pub protocol: Option<String>,
    #[serde(rename = "obfs-param")]
    pub obfs_param: Option<String>,
    #[serde(rename = "protocol-param")]
    pub protocol_param: Option<String>,
    pub udp: Option<bool>,
}
