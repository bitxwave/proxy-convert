use super::base::User;
use crate::protocols::singbox::common::base::{ Handshake, ListenParams };
use indexmap::IndexMap;
use serde::{ Deserialize, Serialize };
use serde_with::skip_serializing_none;

#[skip_serializing_none]
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ShadowTLS {
    pub tag: Option<String>,

    #[serde(flatten)]
    pub listen_params: ListenParams,

    pub version: Option<Version>,
    pub password: Option<String>,
    pub users: Option<Vec<User>>,
    pub handshake: Handshake,
    pub handshake_for_server_name: Option<IndexMap<String, Handshake>>,
    pub strict_mode: Option<bool>,
    pub wildcard_sni: Option<WildcardSNI>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum Version {
    V1 = 1,
    V2,
    V3,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "snake_case")]
pub enum WildcardSNI {
    Off,
    Authed,
    All,
}
