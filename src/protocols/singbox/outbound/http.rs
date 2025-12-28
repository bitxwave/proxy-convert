use crate::singbox::common::{base::Strategy, tls};
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;
use std::collections::HashMap;

#[skip_serializing_none]
#[derive(Default, Serialize, Deserialize, Debug)]
pub struct Http {
    pub tag: String,
    pub server: String,
    pub server_port: u16,
    pub username: Option<String>,
    pub password: Option<String>,
    pub path: Option<String>,
    pub headers: Option<HashMap<String, String>>,
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
