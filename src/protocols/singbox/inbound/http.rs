use crate::protocols::singbox::common::{ base::ListenParams, tls };
use serde::{ Deserialize, Serialize };
use serde_with::skip_serializing_none;
use super::base::User;

#[skip_serializing_none]
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct HTTP {
    pub tag: Option<String>,
    
    #[serde(flatten)]
    pub listen_params: ListenParams,

    pub users: Option<Vec<User>>,
    pub tls: Option<tls::Inbound>,
    pub set_system_proxy: Option<bool>,
}
