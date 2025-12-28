use crate::singbox::common::base::{Network, Strategy};
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;

#[skip_serializing_none]
#[derive(Default, Serialize, Deserialize, Debug)]
pub struct Wireguard {
    pub tag: String,
    pub server: String,
    pub server_port: u16,
    pub system_interface: Option<bool>,
    pub gso: Option<bool>,
    pub interface_name: Option<String>,
    pub local_address: Option<Vec<String>>,
    pub private_key: Option<String>,
    pub peer_public_key: Option<String>,
    pub pre_shared_key: Option<String>,
    pub reserved: Option<Vec<usize>>,
    pub workers: Option<usize>,
    pub mtu: Option<usize>,
    pub network: Option<Network>,
    pub detour: Option<String>,
    pub bind_interface: Option<String>,
    pub inet4_bind_address: Option<String>,
    pub inet6_bind_address: Option<String>,
    pub routing_mark: Option<usize>,
    pub reuse_addr: Option<bool>,
    pub connect_timeout: Option<String>,
    pub tcp_fast_open: Option<bool>,
    pub tcp_multi_path: Option<bool>,
    pub udp_fragment: Option<bool>,
    pub domain_strategy: Option<Strategy>,
    pub fallback_delay: Option<String>,
}
