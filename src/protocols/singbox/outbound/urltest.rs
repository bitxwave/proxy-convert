use serde::{Deserialize, Serialize};

#[derive(Default, Serialize, Deserialize, Debug)]
pub struct Urltest {
    pub tag: String,
    pub url: Option<String>,
    pub interval: Option<String>,
    pub tolerance: Option<usize>,
    pub idle_timeout: Option<String>,
    pub interrupt_exist_connections: Option<bool>,
    pub outbounds: Vec<String>,
}
