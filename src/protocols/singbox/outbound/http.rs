use crate::protocols::singbox::common::{ base::DialParams, tls };
use serde::{ Deserialize, Serialize };
use serde_with::skip_serializing_none;
use indexmap::IndexMap;

#[skip_serializing_none]
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct HTTP {
    pub tag: String,
    pub server: String,
    pub server_port: u16,
    pub username: Option<String>,
    pub password: Option<String>,
    pub path: Option<String>,
    pub headers: Option<IndexMap<String, String>>,
    pub tls: Option<tls::Outbound>,
    
    #[serde(flatten)]
    pub dial_params: DialParams,
}
