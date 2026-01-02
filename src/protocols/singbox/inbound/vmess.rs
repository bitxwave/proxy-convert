use crate::protocols::singbox::common::{base::ListenParams, multiplex::Multiplex, tls, transport::Transport};
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;

#[skip_serializing_none]
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct VMess {
    pub tag: Option<String>,

    #[serde(flatten)]
    pub listen_params: ListenParams,

    pub users: Vec<User>,
    pub tls: Option<tls::Inbound>,
    pub multiplex: Option<Multiplex>,
    pub transport: Option<Transport>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct User {
    pub name: String,
    pub uuid: String,
    #[serde(rename = "camelcase")]
    pub alter_id: u32,
}
