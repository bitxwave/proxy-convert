use super::rule::Rule;
use crate::singbox::common::base::{LogicalMode, Network, QueryType, SingleOrMultipleValue};
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;

#[derive(Serialize, Deserialize, Debug)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum RuleSet {
    Remote(Remote),
    Local(Local),
    Inline(Inline),
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Remote {
    tag: String,
    format: Format,
    url: String,
    download_detour: String,
    update_interval: String,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "lowercase")]
pub enum Format {
    Source,
    Binary,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Local {
    tag: String,
    format: Format,
    path: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Inline {
    tag: String,
    rules: Vec<HeadlessRule>,
}

#[skip_serializing_none]
#[derive(Serialize, Deserialize, Debug)]
pub struct HeadlessRule {
    query_type: Option<SingleOrMultipleValue<QueryType>>,
    network: Option<SingleOrMultipleValue<Network>>,
    domain: Option<SingleOrMultipleValue>,
    domain_suffix: Option<SingleOrMultipleValue>,
    domain_keyword: Option<SingleOrMultipleValue>,
    domain_regex: Option<SingleOrMultipleValue>,
    source_ip_cidr: Option<SingleOrMultipleValue>,
    ip_cidr: Option<SingleOrMultipleValue>,
    source_port: Option<SingleOrMultipleValue<u16>>,
    source_port_range: Option<SingleOrMultipleValue>,
    port: Option<SingleOrMultipleValue<u16>>,
    port_range: Option<SingleOrMultipleValue>,
    process_name: Option<SingleOrMultipleValue>,
    process_path: Option<SingleOrMultipleValue>,
    package_name: Option<SingleOrMultipleValue>,
    wifi_ssid: Option<SingleOrMultipleValue>,
    wifi_bssid: Option<SingleOrMultipleValue>,
    invert: Option<bool>,
    mode: Option<LogicalMode>,
    rules: Option<Vec<Rule>>,
}
