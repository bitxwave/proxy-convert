use crate::protocols::singbox::{common::{
    base::{Network, DialParams},
    tls,
}};
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;

#[skip_serializing_none]
#[derive(Default, Serialize, Deserialize, Debug, Clone)]
pub struct TUIC {
    pub tag: String,
    pub server: String,
    pub server_port: u16,
    pub uuid: String,
    pub password: Option<String>,
    pub congestion_control: Option<CongestionControl>,
    pub udp_relay_mode: Option<UdpRelayMode>,
    pub udp_over_stream: Option<bool>,
    pub zero_rtt_handshake: Option<bool>,
    pub heartbeat: Option<String>,
    pub network: Option<Network>,
    pub tls: Option<tls::Outbound>,
    
    #[serde(flatten)]
    pub dial_params: DialParams,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "snake_case")]
pub enum CongestionControl {
    Cubic,
    NewReno,
    Bbr,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "snake_case")]
pub enum UdpRelayMode {
    Native,
    Quic
}