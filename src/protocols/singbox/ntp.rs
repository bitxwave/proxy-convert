use crate::protocols::singbox::common::base::DialParams;
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;

#[skip_serializing_none]
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct NTP {
    pub enabled: Option<bool>,
    pub server: String,
    pub server_port: Option<u16>,
    pub interval: Option<String>,

    #[serde(flatten)]
    pub dial_params: DialParams,
}