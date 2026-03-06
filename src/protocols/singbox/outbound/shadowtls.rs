use crate::protocols::singbox::common::{base::DialParams, tls};
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;

#[skip_serializing_none]
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ShadowTLS {
    pub tag: String,
    pub server: String,
    pub server_port: u16,
    pub version: Option<ShadowTLSVersion>,
    pub password: Option<String>,
    pub tls: tls::Outbound,

    #[serde(flatten)]
    pub dial_params: DialParams,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum ShadowTLSVersion {
    V1 = 1,
    V2,
    V3,
}
