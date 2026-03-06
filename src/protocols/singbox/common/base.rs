use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;

#[derive(Serialize, Deserialize, Debug, Clone)]
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

#[derive(Serialize, Deserialize, Debug, Clone)]
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

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum IpVersion {
    V4 = 4,
    V6 = 6,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(untagged)]
pub enum QueryType {
    Code(u16),
    Name(String),
}

#[derive(Serialize, Deserialize, Debug, Clone)]
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

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "lowercase")]
pub enum LogicalMode {
    And,
    Or,
}

#[skip_serializing_none]
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Handshake {
    pub server: String,
    pub server_port: u16,

    #[serde(flatten)]
    pub dial_params: Option<DialParams>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
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
#[derive(Default, Serialize, Deserialize, Debug, Clone)]
pub struct ListenParams {
    listen: Option<String>,
    listen_port: Option<u16>,
    bind_interface: Option<String>,
    routing_mark: Option<u32>,
    reuse_addr: Option<bool>,
    netns: Option<String>,
    tcp_fast_open: Option<bool>,
    tcp_multi_path: Option<bool>,
    disable_tcp_keep_alive: Option<bool>,
    tcp_keep_alive: Option<String>,
    tcp_keep_alive_interval: Option<String>,
    udp_fragment: Option<bool>,
    udp_timeout: Option<String>,
    detour: Option<String>,
}

#[skip_serializing_none]
#[derive(Default, Serialize, Deserialize, Debug, Clone)]
pub struct DialParams {
    pub detour: Option<String>,
    pub bind_interface: Option<String>,
    pub inet4_bind_address: Option<String>,
    pub inet6_bind_address: Option<String>,
    /// Only supported on Linux.
    pub routing_mark: Option<usize>,
    pub reuse_addr: Option<bool>,
    /// Only supported on Linux.
    pub netns: Option<String>,
    pub connect_timeout: Option<String>,
    pub tcp_fast_open: Option<bool>,
    pub tcp_multi_path: Option<bool>,
    pub disable_tcp_keep_alive: Option<bool>,
    pub tcp_keep_alive: Option<String>,
    pub tcp_keep_alive_interval: Option<String>,
    pub udp_fragment: Option<bool>,
    pub domain_resolver: Option<DomainResolver>,
    pub network_strategy: Option<NetworkStrategy>,
    pub network_type: Option<Vec<NetworkType>>,
    pub fallback_network_type: Option<Vec<NetworkType>>,
    pub fallback_delay: Option<u64>,
}

#[skip_serializing_none]
#[derive(Default, Serialize, Deserialize, Debug, Clone)]
pub struct DomainResolver {
    pub server: String,
    pub strategy: Option<Strategy>,
    pub disable_cache: Option<bool>,
    pub rewrite_ttl: Option<u32>,
    pub client_subnet: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "snake_case")]
pub enum NetworkStrategy {
    Default,
    Hybrid,
    Fallback,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "snake_case")]
pub enum NetworkType {
    Wifi,
    Cellular,
    Ethernet,
    Other,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "snake_case")]
pub enum ClashMode {
    Direct,
    Global,
    Rule,
}