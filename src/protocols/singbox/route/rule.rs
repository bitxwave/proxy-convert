use crate::protocols::singbox::common::base::{
    IpVersion, LogicalMode, Network, NetworkType, SingleOrMultipleValue, Strategy,
};
use indexmap::IndexMap;
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;

#[skip_serializing_none]
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(untagged)]
pub enum Rule {
    Logical(LogicalRule),
    Basic(BasicRule),
}

#[skip_serializing_none]
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct BasicRule {
    pub inbound: Option<SingleOrMultipleValue>,
    pub ip_version: Option<IpVersion>,
    pub network: Option<Network>,
    pub auth_user: Option<SingleOrMultipleValue>,
    pub protocol: Option<SingleOrMultipleValue<Protocol>>,
    pub client: Option<SingleOrMultipleValue<ProtocolSniffClient>>,
    pub domain: Option<SingleOrMultipleValue>,
    pub domain_suffix: Option<SingleOrMultipleValue>,
    pub domain_keyword: Option<SingleOrMultipleValue>,
    pub domain_regex: Option<SingleOrMultipleValue>,
    pub source_ip_cidr: Option<SingleOrMultipleValue>,
    pub source_ip_is_private: Option<bool>,
    pub ip_cidr: Option<SingleOrMultipleValue>,
    pub ip_is_private: Option<bool>,
    pub ip_accept_any: Option<bool>,
    pub source_port: Option<SingleOrMultipleValue<u16>>,
    pub source_port_range: Option<SingleOrMultipleValue>,
    pub port: Option<SingleOrMultipleValue<u16>>,
    pub port_range: Option<SingleOrMultipleValue>,
    pub process_name: Option<SingleOrMultipleValue>,
    pub process_path: Option<SingleOrMultipleValue>,
    pub process_path_regex: Option<SingleOrMultipleValue>,
    pub package_name: Option<SingleOrMultipleValue>,
    pub user: Option<SingleOrMultipleValue>,
    pub user_id: Option<SingleOrMultipleValue<u32>>,
    pub clash_mode: Option<String>,
    pub network_type: Option<SingleOrMultipleValue<NetworkType>>,
    pub network_is_expensive: Option<bool>,
    pub network_is_constrained: Option<bool>,
    pub interface_address: Option<IndexMap<String, SingleOrMultipleValue>>,
    pub network_interface_address: Option<IndexMap<String, SingleOrMultipleValue>>,
    pub default_interface_address: Option<SingleOrMultipleValue<String>>,
    pub wifi_ssid: Option<SingleOrMultipleValue>,
    pub wifi_bssid: Option<SingleOrMultipleValue>,
    pub preferred_by: Option<SingleOrMultipleValue>,
    pub rule_set: Option<SingleOrMultipleValue>,
    pub rule_set_ip_cidr_match_source: Option<SingleOrMultipleValue>,
    pub invert: Option<bool>,
    pub action: Option<RuleAction>,
    pub outbound: Option<String>,
    pub strategy: Option<Strategy>
}

#[skip_serializing_none]
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct LogicalRule {
    pub r#type: String,
    pub mode: LogicalMode,
    pub rules: Vec<BasicRule>,
    pub action: RuleAction,
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
    Ssh,
    Rdp,
    Ntp,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum RuleAction {
    Route,
    Bypass,
    Reject,
    HijackDns,
    RouteOptions,
    Sniff,
    Resolve,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ProtocolSniffClient {
    QuicClient(QuicClient),
    SshClient(String),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum QuicClient {
    Chromium,
    Safari,
    Firefox,
    QuicGo,
}
