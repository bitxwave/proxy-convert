use crate::protocols::singbox::common::{
    base::{DialParams, Network},
    tls,
};
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;

#[skip_serializing_none]
#[derive(Default, Serialize, Deserialize, Debug, Clone)]
pub struct Hysteria {
    pub tag: String,
    pub server: String,
    pub server_port: u16,
    pub server_ports: Option<Vec<u16>>,
    pub hop_interval: Option<String>,
    pub up: String,
    pub up_mbps: u32,
    pub down: String,
    pub down_mbps: u32,
    pub obfs: Option<String>,
    pub auth: Option<String>,
    pub auth_str: Option<String>,
    pub recv_window_conn: Option<u32>,
    pub recv_window: Option<u32>,
    pub disable_mtu_discovery: Option<bool>,
    pub network: Option<Network>,
    pub tls: Option<tls::Outbound>,
    
    #[serde(flatten)]
    pub dial_params: DialParams,
}
