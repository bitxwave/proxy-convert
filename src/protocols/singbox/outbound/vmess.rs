use crate::protocols::singbox::common::{
    base::{Network, DialParams},
    multiplex::Multiplex,
    tls,
    transport::Transport,
};
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;

#[skip_serializing_none]
#[derive(Default, Serialize, Deserialize, Debug, Clone)]
pub struct VMess {
    pub tag: String,
    pub server: String,
    pub server_port: u16,
    pub uuid: String,
    pub security: Option<String>,
    pub alter_id: Option<u32>,
    pub global_padding: Option<bool>,
    pub authenticated_length: Option<bool>,
    pub network: Option<Network>,
    pub tls: Option<tls::Outbound>,
    pub packet_encoding: Option<String>,
    pub transport: Option<Transport>,
    pub multiplex: Option<Multiplex>,
    
    #[serde(flatten)]
    pub dial_params: DialParams,
}
