use crate::protocols::singbox::{common::{ base::DialParams, tls }, outbound::base::UdpOverTcp};
use serde::{ Deserialize, Serialize };
use serde_with::skip_serializing_none;
use indexmap::IndexMap;

#[skip_serializing_none]
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Naive {
    pub tag: String,
    pub server: String,
    pub server_port: u16,
    pub username: Option<String>,
    pub password: Option<String>,
    pub insecure_concurrency: Option<u32>,
    pub extra_headers: Option<IndexMap<String, String>>,
    pub udp_over_tcp: Option<UdpOverTcp>,
    pub quic: Option<bool>,
    pub quic_congestion_control: Option<QuicCongestionControl>,
    pub tls: Option<tls::Outbound>,

    #[serde(flatten)]
    pub dial_params: DialParams,
}


#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "snake_case")]
pub enum QuicCongestionControl {
    Bbr,
    Bbr2,
    Cubic,
    Reno,
}