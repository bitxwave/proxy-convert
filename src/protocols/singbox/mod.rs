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

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Config {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub log: Option<log::Log>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dns: Option<dns::DNS>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub inbounds: Option<Vec<inbound::Inbound>>,
    #[serde(default)]
    pub outbounds: Vec<outbound::Outbound>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub route: Option<route::Route>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub experimental: Option<experimental::Experimental>,
    /// Capture unknown fields
    #[serde(flatten)]
    pub extra: HashMap<String, serde_json::Value>,
}

/// Protocol name
pub const PROTOCOL_NAME: &str = "singbox";

/// Configuration file extension
pub const CONFIG_EXT: &str = "json";

/// Generate default Sing-box configuration template
pub fn generate_default_template() -> String {
    default_template::generate()
}
