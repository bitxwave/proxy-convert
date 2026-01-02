use crate::protocols::singbox::common::base::{ Network, DialParams };
use super::base::UdpOverTcp;
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;

#[skip_serializing_none]
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Socks {
    pub tag: String,
    pub server: String,
    pub server_port: u16,
    pub version: Option<String>,
    pub username: Option<String>,
    pub password: Option<String>,
    pub network: Option<Network>,
    pub udp_over_tcp: Option<UdpOverTcp>,
    
    #[serde(flatten)]
    pub dial_params: DialParams,
}
