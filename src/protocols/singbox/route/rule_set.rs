use crate::protocols::singbox::common::base::{
    LogicalMode, Network, NetworkType, QueryType, SingleOrMultipleValue,
};
use indexmap::IndexMap;
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum RuleSet {
    Remote(Remote),
    Local(Local),
    Inline(Inline),
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Remote {
    tag: String,
    format: Format,
    url: String,
    download_detour: Option<String>,
    update_interval: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "lowercase")]
pub enum Format {
    Source,
    Binary,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Local {
    tag: String,
    format: Format,
    path: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Inline {
    tag: String,
    rules: Vec<HeadlessRule>,
}

#[skip_serializing_none]
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(untagged)]
pub enum HeadlessRule {
    Logical(LogicalRule),
    Basic(BasicRule),
}

#[skip_serializing_none]
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct BasicRule {
    pub query_type: Option<SingleOrMultipleValue<QueryType>>,
    pub network: Option<SingleOrMultipleValue<Network>>,
    pub domain: Option<SingleOrMultipleValue>,
    pub domain_suffix: Option<SingleOrMultipleValue>,
    pub domain_keyword: Option<SingleOrMultipleValue>,
    pub domain_regex: Option<SingleOrMultipleValue>,
    pub source_ip_cidr: Option<SingleOrMultipleValue>,
    pub ip_cidr: Option<SingleOrMultipleValue>,
    pub source_port: Option<SingleOrMultipleValue<u16>>,
    pub source_port_range: Option<SingleOrMultipleValue>,
    pub port: Option<SingleOrMultipleValue<u16>>,
    pub port_range: Option<SingleOrMultipleValue>,
    pub process_name: Option<SingleOrMultipleValue>,
    pub process_path: Option<SingleOrMultipleValue>,
    pub package_name: Option<SingleOrMultipleValue>,
    pub network_type: Option<SingleOrMultipleValue<NetworkType>>,
    pub network_is_expensive: Option<bool>,
    pub network_is_constrained: Option<bool>,
    pub network_interface_address: Option<IndexMap<String, SingleOrMultipleValue>>,
    pub default_interface_address: Option<SingleOrMultipleValue<String>>,
    pub wifi_ssid: Option<SingleOrMultipleValue>,
    pub wifi_bssid: Option<SingleOrMultipleValue>,
    pub invert: Option<bool>,
}

#[skip_serializing_none]
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct LogicalRule {
    pub r#type: String,
    pub mode: LogicalMode,
    pub rules: Vec<BasicRule>,
    pub invert: Option<bool>,
}
