use crate::protocols::singbox::common::{base::{Network, DialParams}, multiplex::Multiplex, tls, transport::Transport};
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;

#[skip_serializing_none]
#[derive(Default, Serialize, Deserialize, Debug, Clone)]
pub struct Trojan {
    pub tag: String,
    pub server: String,
    pub server_port: u16,
    pub password: String,
    pub network: Option<Network>,
    pub tls: Option<tls::Outbound>,
    pub multiplex: Option<Multiplex>,
    pub transport: Option<Transport>,
    
    #[serde(flatten)]
    pub dial_params: DialParams,
}
