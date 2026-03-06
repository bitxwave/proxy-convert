use crate::protocols::singbox::common::base::{ SingleOrMultipleValue, Stack, ListenParams };
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;

#[skip_serializing_none]
#[derive(Default, Serialize, Deserialize, Debug, Clone)]
pub struct Tun {
    pub tag: Option<String>,
    pub interface_name: Option<String>,
    pub address: Option<SingleOrMultipleValue>,
    pub mtu: Option<u32>,
    pub auto_route: Option<bool>,
    pub iproute2_table_index: Option<u32>,
    pub iproute2_rule_index: Option<u32>,
    pub auto_redirect: Option<bool>,
    pub auto_redirect_input_mark: Option<String>,
    pub auto_redirect_output_mark: Option<String>,
    pub auto_redirect_reset_mark: Option<String>,
    pub auto_redirect_nfqueue: Option<u32>,
    pub exclude_mptcp: Option<bool>,
    pub loopback_address: Option<SingleOrMultipleValue>,
    pub strict_route: Option<bool>,
    pub route_address: Option<SingleOrMultipleValue>,
    pub route_exclude_address: Option<SingleOrMultipleValue>,
    pub route_address_set: Option<SingleOrMultipleValue>,
    pub route_exclude_address_set: Option<SingleOrMultipleValue>,
    pub endpoint_independent_nat: Option<bool>,
    pub udp_timeout: Option<String>,
    pub stack: Option<Stack>,
    pub include_interface: Option<SingleOrMultipleValue>,
    pub exclude_interface: Option<SingleOrMultipleValue>,
    pub include_uid: Option<SingleOrMultipleValue<u32>>,
    pub include_uid_range: Option<SingleOrMultipleValue>,
    pub exclude_uid: Option<SingleOrMultipleValue<u32>>,
    pub exclude_uid_range: Option<SingleOrMultipleValue>,
    pub include_android_user: Option<SingleOrMultipleValue<u32>>,
    pub include_package: Option<SingleOrMultipleValue>,
    pub exclude_package: Option<SingleOrMultipleValue>,
    pub platform: Option<Platform>,

    #[serde(flatten)]
    pub listen_params: ListenParams,
}

#[skip_serializing_none]
#[derive(Default, Serialize, Deserialize, Debug, Clone)]
pub struct Platform {
    pub http_proxy: Option<HttpProxy>,
}

#[skip_serializing_none]
#[derive(Default, Serialize, Deserialize, Debug, Clone)]
pub struct HttpProxy {
    pub server: String,
    pub server_port: u16,
    pub enabled: Option<bool>,
    pub bypass_domain: Option<SingleOrMultipleValue>,
    pub match_domain: Option<SingleOrMultipleValue>,
}
