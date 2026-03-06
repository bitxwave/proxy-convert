use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(untagged)]
pub enum Multiplex {
    Inbound {
        enabled: bool,
        padding: bool,
        brutal: Brutal,
    },
    Outbound {
        enabled: bool,
        protocol: MultiplexProtocol,
        max_connections: u32,
        min_streams: u32,
        max_streams: u32,
        padding: bool,
        brutal: Brutal,
    },
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "lowercase")]
pub enum MultiplexProtocol {
    Smux,
    Yamux,
    H2mux,
}

impl Default for MultiplexProtocol {
    fn default() -> Self {
        MultiplexProtocol::H2mux
    }
}

#[derive(Default, Serialize, Deserialize, Debug, Clone)]
pub struct Brutal {
    #[serde(skip_serializing_if = "Option::is_none")]
    enabled: Option<bool>,
    up_mbps: u32,
    down_mbps: u32,
}
