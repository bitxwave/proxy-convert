//! V2Ray Protocol Support Module

pub mod default_template;
pub mod template_processor;

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// V2Ray configuration
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Config {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub log: Option<Log>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub inbounds: Option<Vec<Inbound>>,
    #[serde(default)]
    pub outbounds: Vec<Outbound>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub routing: Option<Routing>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dns: Option<Dns>,
    /// Capture unknown fields
    #[serde(flatten)]
    pub extra: HashMap<String, serde_json::Value>,
}

/// V2Ray log configuration
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Log {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub loglevel: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub access: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(flatten)]
    pub extra: HashMap<String, serde_json::Value>,
}

/// V2Ray inbound configuration
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Inbound {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub listen: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub protocol: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub settings: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sniffing: Option<serde_json::Value>,
    #[serde(flatten)]
    pub extra: HashMap<String, serde_json::Value>,
}

/// V2Ray outbound configuration
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Outbound {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tag: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub protocol: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub settings: Option<serde_json::Value>,
    #[serde(rename = "streamSettings", skip_serializing_if = "Option::is_none")]
    pub stream_settings: Option<serde_json::Value>,
    #[serde(flatten)]
    pub extra: HashMap<String, serde_json::Value>,
}

/// V2Ray routing configuration
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Routing {
    #[serde(rename = "domainStrategy", skip_serializing_if = "Option::is_none")]
    pub domain_strategy: Option<String>,
    #[serde(default)]
    pub rules: Vec<serde_json::Value>,
    #[serde(flatten)]
    pub extra: HashMap<String, serde_json::Value>,
}

/// V2Ray DNS configuration
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Dns {
    #[serde(default)]
    pub servers: Vec<serde_json::Value>,
    #[serde(flatten)]
    pub extra: HashMap<String, serde_json::Value>,
}

/// Protocol name
pub const PROTOCOL_NAME: &str = "v2ray";

/// Configuration file extension
pub const CONFIG_EXT: &str = "json";

/// Generate default V2Ray configuration template
pub fn generate_default_template() -> String {
    default_template::generate()
}
