use super::hysteria::User;
use crate::singbox::common::{base::Strategy, tls};
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;

#[skip_serializing_none]
#[derive(Default, Serialize, Deserialize, Debug)]
pub struct Hysteria2 {
    pub tag: String,
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
    pub up_mbps: Option<usize>,
    pub down_mbps: Option<usize>,
    pub obfs: Option<Obfs>,
    pub users: Option<Vec<User>>,
    pub ignore_client_bandwidth: Option<bool>,
    pub masquerade: Option<String>,
    pub brutal_debug: Option<bool>,
}

#[derive(Default, Serialize, Deserialize, Debug)]
pub struct Obfs {
    pub r#type: String,
    pub password: String,
}
