use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "snake_case")]
pub enum Strategy {
    PreferIpv4,
    PreferIpv6,
    Ipv4Only,
    Ipv6Only,
}

impl Default for Strategy {
    fn default() -> Self {
        Strategy::PreferIpv4
    }
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(untagged)]
pub enum SingleOrMultipleValue<T = String> {
    Single(T),
    Multiple(Vec<T>),
}

impl Default for SingleOrMultipleValue {
    fn default() -> Self {
        SingleOrMultipleValue::Multiple(vec![])
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub enum IpVersion {
    V4 = 4,
    V6 = 6,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(untagged)]
pub enum QueryType {
    Code(usize),
    Name(String),
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "snake_case")]
pub enum Network {
    Tcp,
    Udp,
}

impl Default for Network {
    fn default() -> Self {
        Network::Tcp
    }
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "lowercase")]
pub enum LogicalMode {
    And,
    Or,
}

#[skip_serializing_none]
#[derive(Default, Serialize, Deserialize, Debug)]
pub struct Handshake {
    detour: Option<String>,
    bind_interface: Option<String>,
    inet4_bind_address: Option<String>,
    inet6_bind_address: Option<String>,
    routing_mark: Option<usize>,
    reuse_addr: Option<bool>,
    connect_timeout: Option<String>,
    tcp_fast_open: Option<bool>,
    tcp_multi_path: Option<bool>,
    udp_fragment: Option<bool>,
    domain_strategy: Option<Strategy>,
    fallback_delay: Option<String>,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "lowercase")]
pub enum Stack {
    System,
    Gvisor,
    Mixed,
}

impl Default for Stack {
    fn default() -> Self {
        Stack::Mixed
    }
}

#[skip_serializing_none]
#[derive(Default, Serialize, Deserialize, Debug)]
pub struct ListenParams {
    listen: Option<String>,
    listen_port: Option<u16>,
    tcp_fast_open: Option<bool>,
    tcp_multi_path: Option<bool>,
    udp_fragment: Option<bool>,
    udp_timeout: Option<String>,
    detour: Option<String>,
    sniff: Option<bool>,
    sniff_override_destination: Option<bool>,
    sniff_timeout: Option<String>,
    domain_strategy: Option<Strategy>,
    udp_disable_domain_unmapping: Option<bool>,
}
