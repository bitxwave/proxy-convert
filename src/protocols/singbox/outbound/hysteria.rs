use crate::singbox::common::{
    base::{Network, Strategy},
    tls,
};
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;

#[skip_serializing_none]
#[derive(Default, Serialize, Deserialize, Debug)]
pub struct Hysteria {
    pub tag: String,
    pub server: String,
    pub server_port: u16,
    pub up: String,
    pub up_mbps: usize,
    pub down: String,
    pub down_mbps: usize,
    pub obfs: Option<String>,
    pub auth: Option<String>,
    pub auth_str: Option<String>,
    pub recv_window_conn: Option<usize>,
    pub recv_window: Option<usize>,
    pub disable_mtu_discovery: Option<bool>,
    pub network: Option<Network>,
    pub tls: Option<tls::Outbound>,
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
