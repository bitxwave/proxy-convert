use crate::protocols::singbox::common::{ base::DialParams, tls };
use serde::{ Deserialize, Serialize };
use serde_with::skip_serializing_none;

#[skip_serializing_none]
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AnyTLS {
    pub tag: String,
    pub server: String,
    pub server_port: u16,
    pub password: String,
    pub idle_session_check_interval: Option<String>,
    pub idle_session_timeout: Option<String>,
    pub min_idle_session: u32,
    pub tls: tls::Outbound,
    
    #[serde(flatten)]
    pub dial_params: DialParams,
}
