use super::hysteria::User;
use crate::protocols::singbox::common::{base::ListenParams, tls};
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;

#[skip_serializing_none]
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Hysteria2 {
    pub tag: Option<String>,

    #[serde(flatten)]
    pub listen_params: ListenParams,

    pub up_mbps: Option<usize>,
    pub down_mbps: Option<usize>,
    pub obfs: Option<Obfs>,
    pub users: Option<Vec<User>>,
    pub ignore_client_bandwidth: Option<bool>,
    pub tls: tls::Inbound,
    pub masquerade: Option<String>,
    pub brutal_debug: Option<bool>,
}

#[derive(Default, Serialize, Deserialize, Debug, Clone)]
pub struct Obfs {
    pub r#type: String,
    pub password: String,
}
