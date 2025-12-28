use crate::singbox::common::{
    base::{Network, Strategy},
    multiplex::Multiplex,
    tls,
    transport::Transport,
};
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;

#[skip_serializing_none]
#[derive(Default, Serialize, Deserialize, Debug)]
pub struct Vless {
    pub tag: String,
    pub server: String,
    pub server_port: u16,
    pub uuid: String,
    pub flow: Option<String>,
    pub network: Option<Network>,
    pub tls: Option<tls::Outbound>,
    pub packet_encoding: Option<String>,
    pub multiplex: Option<Multiplex>,
    pub transport: Option<Transport>,
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
