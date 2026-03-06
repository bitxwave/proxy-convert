use crate::protocols::singbox::common::{
    base::{ Network, ListenParams },
    tls,
};
use super::base::User;
use serde::{ Deserialize, Serialize };
use serde_with::skip_serializing_none;

#[skip_serializing_none]
#[derive(Default, Serialize, Deserialize, Debug, Clone)]
pub struct Naive {
    pub tag: Option<String>,
    pub network: Option<Network>,

    #[serde(flatten)]
    pub listen_params: ListenParams,
    
    pub users: Vec<User>,
    pub quic_congestion_control: Option<QuicCongestionControl>,
    pub tls: Option<tls::Inbound>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "snake_case")]
pub enum QuicCongestionControl {
    Bbr,
    BbrStandard,
    Bbr2,
    Bbr2Variant,
    Cubic,
    Reno,
}