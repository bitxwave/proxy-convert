use crate::singbox::common::base::{Network, Strategy};
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;

#[skip_serializing_none]
#[derive(Default, Serialize, Deserialize, Debug)]
pub struct Direct {
    pub tag: String,
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
    pub network: Option<Network>,
    pub override_address: Option<String>,
    pub override_port: Option<u16>,
}
