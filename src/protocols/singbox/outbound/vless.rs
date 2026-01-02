use crate::protocols::singbox::common::{
    base::{DialParams, Network},
    multiplex::Multiplex,
    tls,
    transport::Transport,
};
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;

#[skip_serializing_none]
#[derive(Default, Serialize, Deserialize, Debug, Clone)]
pub struct VLESS {
    pub tag: String,
    pub server: String,
    pub server_port: u16,
    pub uuid: String,
    pub flow: Option<String>,
    pub network: Option<Network>,
    pub tls: Option<tls::Outbound>,
    pub packet_encoding: Option<String>,
    pub multiplex: Option<Multiplex>,
    pub transport: Option<Transport>,

    #[serde(flatten)]
    pub dial_params: DialParams,   
}
