use serde::{Deserialize, Serialize};

#[derive(Default, Serialize, Deserialize, Debug, Clone)]
pub struct Urltest {
    pub tag: String,
    pub outbounds: Vec<String>,
    pub url: Option<String>,
    pub interval: Option<String>,
    pub tolerance: Option<u32>,
    pub idle_timeout: Option<String>,
    pub interrupt_exist_connections: Option<bool>,
}
