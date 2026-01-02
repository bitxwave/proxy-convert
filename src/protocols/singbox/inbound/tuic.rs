use crate::protocols::singbox::common::{base::ListenParams, tls};
use serde::{ Deserialize, Serialize };
use serde_with::skip_serializing_none;

#[skip_serializing_none]
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TUIC {
    pub tag: Option<String>,

    #[serde(flatten)]
    pub listen_params: ListenParams,

    pub users: Vec<User>,
    pub congestion_control: Option<CongestionControl>,
    pub auth_timeout: Option<String>,
    pub zero_rtt_handshake: Option<bool>,
    pub heartbeat: Option<String>,
    pub tls: tls::Inbound,
}

#[derive(Default, Serialize, Deserialize, Debug, Clone)]
pub struct User {
    pub name: String,
    pub uuid: String,
    pub password: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "snake_case")]
pub enum CongestionControl {
    Cubic,
    NewReno,
    Bbr,
}
