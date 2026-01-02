use super::base::UdpOverTcp;
use crate::protocols::singbox::common::{
    base::{ Network, DialParams },
    multiplex::Multiplex,
};
use serde::{ Deserialize, Serialize };
use serde_with::skip_serializing_none;

#[skip_serializing_none]
#[derive(Default, Serialize, Deserialize, Debug, Clone)]
pub struct Shadowsocks {
    pub tag: String,
    pub server: String,
    pub server_port: u16,
    pub method: String,
    pub password: String,
    pub plugin: Option<String>,
    pub plugin_opts: Option<String>,
    pub network: Option<Network>,
    pub udp_over_tcp: Option<UdpOverTcp>,
    pub multiplex: Option<Multiplex>,
    
    #[serde(flatten)]
    pub dial_params: DialParams,
}
