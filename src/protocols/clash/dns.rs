use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "kebab-case")]
pub struct DNS {
    pub enable: Option<bool>,
    pub ipv6: Option<bool>,
    pub default_nameserver: Option<Vec<String>>,
    pub enhanced_mode: Option<String>,
    pub fake_ip_range: Option<String>,
    pub use_hosts: Option<bool>,
    pub nameserver: Option<Vec<String>>,
    pub fallback: Option<Vec<String>>,
    pub fallback_filter: Option<FallbackFilter>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct FallbackFilter {
    pub geoip: Option<bool>,
    #[serde(rename = "ipcidr")]
    pub ip_cidr: Option<Vec<String>>,
}
