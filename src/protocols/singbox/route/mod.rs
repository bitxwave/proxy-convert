pub mod rule;
pub mod rule_set;

use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;

use super::common::base::Strategy;

#[skip_serializing_none]
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Route {
    pub default_domain_resolver: StringOrDomainResolver,
    pub rules: Vec<rule::Rule>,
    pub rule_set: Vec<rule_set::RuleSet>,
    pub r#final: String,
    pub auto_detect_interface: Option<bool>,
    pub override_android_vpn: Option<bool>,
    pub default_interface: Option<String>,
    pub default_mark: Option<usize>,
}

impl Default for Route {
    fn default() -> Self {
        Self {
            default_domain_resolver: StringOrDomainResolver::Str("default".to_string()),
            rules: Vec::new(),
            rule_set: Vec::new(),
            r#final: "DIRECT".to_string(),
            auto_detect_interface: Some(true),
            override_android_vpn: None,
            default_interface: None,
            default_mark: None,
        }
    }
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
