pub mod rule;
pub mod rule_set;

use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;

use crate::protocols::singbox::common::base::{NetworkStrategy, NetworkType};

use super::common::base::Strategy;

#[skip_serializing_none]
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Route {
    pub rules: Vec<rule::Rule>,
    pub rule_set: Vec<rule_set::RuleSet>,
    pub r#final: Option<String>,
    pub auto_detect_interface: Option<bool>,
    pub override_android_vpn: Option<bool>,
    pub default_interface: Option<String>,
    pub default_mark: Option<u32>,
    pub default_domain_resolver: Option<StringOrDomainResolver>,
    pub default_network_strategy: Option<NetworkStrategy>,
    pub default_network_type: Option<Vec<NetworkType>>,
    pub default_fallback_network_type: Option<Vec<NetworkType>>,
    pub default_fallback_delay: Option<u32>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(untagged)]
pub enum StringOrDomainResolver {
    Str(String),
    DomainResolver(DomainResolver),
}

#[skip_serializing_none]
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DomainResolver {
    server: String,
    strategy: Option<Strategy>,
    disable_cache: Option<bool>,
    rewrite_ttl: Option<i32>,
    client_subnet: Option<String>,
}
