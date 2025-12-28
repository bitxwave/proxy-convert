use crate::singbox::common::base::Strategy;
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;

#[skip_serializing_none]
#[derive(Default, Serialize, Deserialize, Debug)]
pub struct Direct {
    pub tag: String,
    pub override_address: Option<String>,
    pub override_port: Option<u16>,
    pub proxy_protocol: Option<ProxyProtocol>,
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

#[derive(Serialize, Deserialize, Debug)]
pub enum ProxyProtocol {
    V1 = 1,
    V2,
}
