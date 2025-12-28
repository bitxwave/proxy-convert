use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;

#[skip_serializing_none]
#[derive(Default, Serialize, Deserialize, Debug)]
pub struct Snell {
    pub name: String,
    #[serde(rename = "interface-name")]
    pub interface_name: Option<String>,
    #[serde(rename = "routing-mark")]
    pub routing_mark: Option<usize>,
    pub server: String,
    pub port: u16,
    pub psk: Option<String>,
    pub version: Option<usize>,
    #[serde(rename = "obfs-opts")]
    pub obfs_opts: Option<ObfsOpts>,
}

#[skip_serializing_none]
#[derive(Default, Serialize, Deserialize, Debug)]
pub struct ObfsOpts {
    pub mode: Option<String>,
    pub host: Option<String>,
}
