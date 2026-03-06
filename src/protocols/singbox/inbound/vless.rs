use crate::protocols::singbox::common::{ base::{ ListenParams }, multiplex::Multiplex, tls, transport::Transport };
use serde::{ Deserialize, Serialize };
use serde_with::skip_serializing_none;

#[skip_serializing_none]
#[derive(Default, Serialize, Deserialize, Debug, Clone)]
pub struct VLESS {
    pub tag: Option<String>,

    #[serde(flatten)]
    pub listen_params: ListenParams,

    pub users: Vec<User>,
    pub tls: Option<tls::Inbound>,
    pub multiplex: Option<Multiplex>,
    pub transport: Option<Transport>,
}

#[derive(Default, Serialize, Deserialize, Debug, Clone)]
pub struct User {
    pub uuid: String,
    pub name: Option<String>,
    pub flow: Option<String>,
}
