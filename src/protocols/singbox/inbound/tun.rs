use crate::singbox::common::base::{SingleOrMultipleValue, Stack, Strategy};
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;

#[skip_serializing_none]
#[derive(Default, Serialize, Deserialize, Debug)]
pub struct Tun {
    pub tag: String,
    pub address: Option<SingleOrMultipleValue>,
    pub interface_name: Option<String>,
    pub mtu: Option<usize>,
    pub gso: Option<bool>,
    pub auto_route: Option<bool>,
    pub iproute2_table_index: Option<usize>,
    pub iproute2_rule_index: Option<usize>,
    pub auto_redirect: Option<bool>,
    pub auto_redirect_input_mark: Option<String>,
    pub auto_redirect_output_mark: Option<String>,
    pub strict_route: Option<bool>,
    pub route_address: Option<SingleOrMultipleValue>,
    pub route_exclude_address: Option<SingleOrMultipleValue>,
    pub route_address_set: Option<SingleOrMultipleValue>,
    pub route_exclude_address_set: Option<SingleOrMultipleValue>,
    pub endpoint_independent_nat: Option<bool>,
    pub stack: Option<Stack>,
    pub include_interface: Option<SingleOrMultipleValue>,
    pub exclude_interface: Option<SingleOrMultipleValue>,
    pub include_uid: Option<SingleOrMultipleValue<usize>>,
    pub include_uid_range: Option<SingleOrMultipleValue>,
    pub exclude_uid: Option<SingleOrMultipleValue<usize>>,
    pub exclude_uid_range: Option<SingleOrMultipleValue>,
    pub include_android_user: Option<SingleOrMultipleValue<usize>>,
    pub include_package: Option<SingleOrMultipleValue>,
    pub exclude_package: Option<SingleOrMultipleValue>,
    pub platform: Option<Platform>,
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
}

#[skip_serializing_none]
#[derive(Default, Serialize, Deserialize, Debug)]
pub struct Platform {
    pub http_proxy: Option<HttpProxy>,
}

#[skip_serializing_none]
#[derive(Default, Serialize, Deserialize, Debug)]
pub struct HttpProxy {
    pub server: String,
    pub server_port: u16,
    pub enabled: Option<bool>,
    pub bypass_domain: Option<SingleOrMultipleValue>,
    pub match_domain: Option<SingleOrMultipleValue>,
}
