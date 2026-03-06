use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(untagged)]
pub enum UdpOverTcp {
    Enabled(bool),
    Option {
        enabled: bool,
        version: UdpOverTcpVersion,
    },
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum UdpOverTcpVersion {
    V1 = 1,
    V2,
}
