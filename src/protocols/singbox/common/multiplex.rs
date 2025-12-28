use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
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
        max_connections: usize,
        min_streams: usize,
        max_streams: usize,
        padding: bool,
        brutal: Brutal,
    },
}

#[derive(Serialize, Deserialize, Debug)]
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

#[derive(Default, Serialize, Deserialize, Debug)]
pub struct Brutal {
    #[serde(skip_serializing_if = "Option::is_none")]
    enabled: Option<bool>,
    up_mbps: usize,
    down_mbps: usize,
}
