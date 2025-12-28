use super::base::User;
use crate::singbox::common::base::{Handshake, Strategy};
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;

#[skip_serializing_none]
#[derive(Default, Serialize, Deserialize, Debug)]
pub struct Shadowtls {
    pub tag: String,
    pub handshake: Handshake,
    pub handshake_for_server_name: Handshake,
    pub listen: Option<String>,
    pub listen_port: Option<u16>,
    pub tcp_fast_open: Option<bool>,
    pub tcp_multi_path: Option<bool>,
    pub udp_fragment: Option<bool>,
    pub udp_timeout: Option<String>,
    pub detour: Option<String>,
    pub sniff: Option<bool>,
    pub sniff_override_destination: Option<bool>,
    pub sniff_timeout: Option<String>,
    pub domain_strategy: Option<Strategy>,
    pub udp_disable_domain_unmapping: Option<bool>,
    pub version: Option<Version>,
    pub users: Option<Vec<User>>,
    pub strict_mode: Option<bool>,
}

#[derive(Serialize, Deserialize, Debug)]
pub enum Version {
    V1 = 1,
    V2,
    V3,
}
