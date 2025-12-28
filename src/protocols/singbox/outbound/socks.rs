use super::base::UdpOverTcp;
use crate::singbox::common::base::{Network, Strategy};
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;

#[skip_serializing_none]
#[derive(Default, Serialize, Deserialize, Debug)]
pub struct Socks {
    pub tag: String,
    pub server: String,
    pub server_port: u16,
    pub version: Option<String>,
    pub username: Option<String>,
    pub password: Option<String>,
    pub network: Option<Network>,
    pub udp_over_tcp: Option<UdpOverTcp>,
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
