use crate::protocols::singbox::common::{base::ListenParams, tls};
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;

#[skip_serializing_none]
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Hysteria {
    pub tag: Option<String>,

    #[serde(flatten)]
    pub listen_params: ListenParams,

    pub up: String,
    pub up_mbps: u32,
    pub down: String,
    pub down_mbps: u32,
    pub obfs: Option<String>,
    pub users: Option<Vec<User>>,
    pub recv_window_conn: Option<usize>,
    pub recv_window_client: Option<usize>,
    pub max_conn_client: Option<usize>,
    pub disable_mtu_discovery: Option<bool>,
    pub tls: tls::Inbound,
}

#[derive(Default, Serialize, Deserialize, Debug, Clone)]
pub struct User {
    pub name: String,
    pub auth: String,
    pub auth_str: usize,
}