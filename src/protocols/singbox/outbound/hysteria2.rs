use crate::protocols::singbox::{
    common::{
        base::{DialParams, Network},
        tls,
    },
    inbound::hysteria2::Obfs,
};
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;

#[skip_serializing_none]
#[derive(Default, Serialize, Deserialize, Debug, Clone)]
pub struct Hysteria2 {
    pub tag: String,
    pub server: String,
    pub server_port: u16,
    pub server_ports: Option<Vec<u16>>,
    pub hop_interval: Option<String>,
    pub up_mbps: Option<u32>,
    pub down_mbps: Option<u32>,
    pub obfs: Option<Obfs>,
    pub password: Option<String>,
    pub network: Option<Network>,
    pub tls: Option<tls::Outbound>,
    pub brutal_debug: Option<bool>,
    
    #[serde(flatten)]
    pub dial_params: DialParams,
}
