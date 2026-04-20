use crate::protocols::singbox::common::base::DialParams;
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;

#[skip_serializing_none]
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct WireGuard {
    pub tag: String,
    pub server: Option<String>,
    pub server_port: Option<u16>,
    pub system_interface: Option<bool>,
    pub gso: Option<bool>,
    pub interface_name: Option<String>,
    pub local_address: Option<Vec<String>>,
    pub private_key: Option<String>,
    pub peers: Option<Vec<WireGuardPeer>>,
    pub mtu: Option<u16>,

    #[serde(flatten)]
    pub dial_params: DialParams,
}

#[skip_serializing_none]
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct WireGuardPeer {
    pub server: Option<String>,
    pub server_port: Option<u16>,
    pub public_key: Option<String>,
    pub pre_shared_key: Option<String>,
    pub allowed_ips: Option<Vec<String>>,
    pub reserved: Option<Vec<u8>>,
}
