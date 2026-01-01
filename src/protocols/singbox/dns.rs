use super::common::base::{
    IpVersion, LogicalMode, Network, QueryType, SingleOrMultipleValue, Strategy,
};
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;

#[skip_serializing_none]
#[derive(Default, Serialize, Deserialize, Debug, Clone)]
pub struct DNS {
    pub servers: Vec<Server>,
    pub rules: Option<Vec<Rule>>,
    pub r#final: String,
    pub strategy: Option<Strategy>,
    pub disable_cache: Option<bool>,
    pub disable_expire: Option<bool>,
    pub independent_cache: Option<bool>,
    pub reverse_mapping: Option<bool>,
    pub client_subnet: Option<String>,
    pub fakeip: Option<FackIp>,
}

#[skip_serializing_none]
#[derive(Default, Serialize, Deserialize, Debug, Clone)]
pub struct Server {
    tag: String,
    r#type: String,
    server: Option<String>,
    responses: Option<Vec<Response>>,
    domain_resolver: Option<String>,
    detour: Option<String>,
    client_subnet: Option<String>,
}

#[skip_serializing_none]
#[derive(Default, Serialize, Deserialize, Debug, Clone)]
pub struct Response {
    rcode: String,
}

#[skip_serializing_none]
#[derive(Default, Serialize, Deserialize, Debug, Clone)]
pub struct Rule {
    inbound: Option<SingleOrMultipleValue>,
    ip_version: Option<IpVersion>,
    query_type: Option<Vec<QueryType>>,
    network: Option<Network>,
    auth_user: Option<SingleOrMultipleValue>,
    protocol: Option<Vec<Protocol>>,
    domain: Option<SingleOrMultipleValue>,
    domain_suffix: Option<SingleOrMultipleValue>,
    domain_keyword: Option<SingleOrMultipleValue>,
    domain_regex: Option<SingleOrMultipleValue>,
    source_ip_cidr: Option<SingleOrMultipleValue>,
    source_ip_is_private: Option<bool>,
    ip_cidr: Option<SingleOrMultipleValue>,
    ip_is_private: Option<bool>,
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
    rule_set_ip_cidr_match_source: Option<bool>,
    rule_set_ip_cidr_accept_empty: Option<bool>,
    invert: Option<bool>,
    outbound: Option<SingleOrMultipleValue>,
    server: Option<String>,
    disable_cache: Option<bool>,
    client_subnet: Option<String>,
    action: String,
    method: Option<String>,
    no_drop: Option<bool>,
    mode: Option<LogicalMode>,
    strategy: Option<Strategy>,
    rules: Option<Vec<Rule>>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "snake_case")]
pub enum Protocol {
    Http,
    Tls,
    Quic,
    Stun,
    Dns,
    Bittorrent,
    Dtls,
}

#[skip_serializing_none]
#[derive(Default, Serialize, Deserialize, Debug, Clone)]
pub struct FackIp {
    enabled: Option<bool>,
    inet4_range: Option<String>,
    inet6_range: Option<String>,
}
