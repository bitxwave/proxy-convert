use crate::protocols::singbox::common::{
    base::{ ListenParams },
    multiplex::Multiplex,
};
use super::base::User;
use serde::{ Deserialize, Serialize };
use serde_with::skip_serializing_none;

#[skip_serializing_none]
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Shadowsocks {
    pub tag: Option<String>,

    #[serde(default)]
    pub listen_params: ListenParams,

    pub method: String,
    pub password: String,
    pub users: Option<Vec<User>>,
    pub destinations: Option<Vec<Distination>>,
    pub multiplex: Option<Multiplex>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Distination {
    pub name: String,
    pub server: String,
    pub server_port: u16,
    pub password: String,
}
