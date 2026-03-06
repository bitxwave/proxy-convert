//! Sing-box Protocol Support Module

pub mod common;
pub mod default_template;
pub mod dns;
pub mod experimental;
pub mod inbound;
pub mod log;
pub mod outbound;
pub mod route;
pub mod template_processor;
pub mod ntp;
pub mod endpoint;
pub mod certificate;
pub mod service;

use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;

#[skip_serializing_none]
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Config {
    pub log: Option<log::Log>,
    pub dns: Option<dns::DNS>,
    pub ntp: Option<ntp::NTP>,
    pub certificate: Option<certificate::Certificate>,
    pub endpoints: Option<Vec<endpoint::Endpoint>>,
    pub inbounds: Vec<inbound::Inbound>,
    pub outbounds: Vec<outbound::Outbound>,
    pub route: Option<route::Route>,
    pub services: Option<Vec<service::Service>>,
    pub experimental: Option<experimental::Experimental>,
}

/// Protocol name
pub const PROTOCOL_NAME: &str = "singbox";

/// Configuration file extension
pub const CONFIG_EXT: &str = "json";

/// Generate default Sing-box configuration template
pub fn generate_default_template() -> String {
    default_template::generate()
}
