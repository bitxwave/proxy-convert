use crate::singbox::common::{base::Strategy, tls};
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;

#[skip_serializing_none]
#[derive(Default, Serialize, Deserialize, Debug)]
pub struct Hysteria {
    pub tag: String,
    pub up: String,
    pub up_mbps: usize,
    pub down: String,
    pub down_mbps: usize,
    pub tls: tls::Inbound,
    pub listen: Option<String>,
    pub listen_port: Option<u16>,
    pub tcp_fast_open: Option<bool>,
    pub tcp_multi_path: Option<bool>,
    pub udp_fragment: Option<bool>,
    pub udp_timeout: Option<String>,
    pub detour: Option<String>,
    pub sniff: Option<bool>,
    pub sniff_override_destination: Option<bool>,
    pub sniff_timeout: Option<String>,
    pub domain_strategy: Option<Strategy>,
    pub udp_disable_domain_unmapping: Option<bool>,
    pub obfs: Option<String>,
    pub users: Option<Vec<User>>,
    pub recv_window_conn: Option<usize>,
    pub recv_window_client: Option<usize>,
    pub max_conn_client: Option<usize>,
    pub disable_mtu_discovery: Option<bool>,
}

#[derive(Default, Serialize, Deserialize, Debug)]
pub struct User {
    pub name: String,
    pub auth: String,
    pub auth_str: usize,
}
