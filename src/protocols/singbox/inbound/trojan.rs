use crate::protocols::singbox::common::{ base::ListenParams, multiplex::Multiplex, tls, transport::Transport };
use super::base::User;
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;
use indexmap::IndexMap;

#[skip_serializing_none]
#[derive(Default, Serialize, Deserialize, Debug, Clone)]
pub struct Trojan {
    pub tag: Option<String>,

    #[serde(flatten)]
    pub listen_params: ListenParams,

    pub users: Vec<User>,
    pub tls: Option<tls::Inbound>,
    pub fallback: Option<Fallback>,
    pub fallback_for_alpn: Option<IndexMap<String, Fallback>>,
    pub multiplex: Option<Multiplex>,
    pub transport: Option<Transport>,
}

#[derive(Default, Serialize, Deserialize, Debug, Clone)]
pub struct Fallback {
    pub server: String,
    pub server_port: u16,
}
