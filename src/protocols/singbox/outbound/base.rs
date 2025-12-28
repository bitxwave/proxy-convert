use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
#[serde(untagged)]
pub enum UdpOverTcp {
    Enabled(bool),
    Option {
        enabled: bool,
        version: UdpOverTcpVersion,
    },
}

#[derive(Serialize, Deserialize, Debug)]
pub enum UdpOverTcpVersion {
    V1 = 1,
    V2,
}
