use crate::singbox::common::base::{IpVersion, LogicalMode, SingleOrMultipleValue};
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;

#[skip_serializing_none]
#[derive(Serialize, Deserialize, Debug)]
pub struct Rule {
    action: String,
    outbound: Option<String>,
    inbound: Option<SingleOrMultipleValue>,
    ip_version: Option<IpVersion>,
    auth_user: Option<SingleOrMultipleValue>,
    protocol: Option<SingleOrMultipleValue>,
    network: Option<SingleOrMultipleValue>,
    domain: Option<SingleOrMultipleValue>,
    domain_suffix: Option<SingleOrMultipleValue>,
    domain_keyword: Option<SingleOrMultipleValue>,
    domain_regex: Option<SingleOrMultipleValue>,
    source_ip_cidr: Option<SingleOrMultipleValue>,
    ip_is_private: Option<bool>,
    ip_cidr: Option<SingleOrMultipleValue>,
    source_ip_is_private: Option<bool>,
    source_port: Option<Vec<u16>>,
    source_port_range: Option<SingleOrMultipleValue>,
    port: Option<Vec<u16>>,
    port_range: Option<SingleOrMultipleValue>,
    process_name: Option<SingleOrMultipleValue>,
    process_path: Option<SingleOrMultipleValue>,
    package_name: Option<SingleOrMultipleValue>,
    user: Option<SingleOrMultipleValue>,
    user_id: Option<Vec<usize>>,
    clash_mode: Option<String>,
    wifi_ssid: Option<SingleOrMultipleValue>,
    wifi_bssid: Option<SingleOrMultipleValue>,
    rule_set: Option<SingleOrMultipleValue>,
    rule_set_ip_cidr_match_source: Option<SingleOrMultipleValue>,
    invert: Option<SingleOrMultipleValue>,
    mode: Option<LogicalMode>,
    method: Option<String>,
    no_drop: Option<bool>,
}
