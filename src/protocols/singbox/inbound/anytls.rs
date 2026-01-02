use crate::protocols::singbox::common::{ base::ListenParams, tls };
use super::base::User;
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;

#[skip_serializing_none]
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AnyTLS {
    pub tag: Option<String>,

    #[serde(flatten)]
    pub listen_params: ListenParams,

    pub users: Vec<User>,
    pub padding_scheme: Option<Vec<String>>,
    pub tls: Option<tls::Inbound>,
}
