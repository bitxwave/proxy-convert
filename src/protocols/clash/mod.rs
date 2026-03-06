//! Clash Protocol Support Module

pub mod default_template;
pub mod dns;
pub mod proxy;
pub mod proxy_group;
pub mod template_processor;

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "kebab-case")]
pub struct Config {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mixed_port: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allow_lan: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bind_address: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mode: Option<Mode>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub log_level: Option<LogLevel>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub external_controller: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dns: Option<dns::DNS>,
    #[serde(default)]
    pub proxies: Vec<proxy::Proxy>,
    #[serde(default)]
    pub proxy_groups: Vec<proxy_group::ProxyGroup>,
    #[serde(default)]
    pub rules: Vec<String>,
    /// Capture unknown fields
    #[serde(flatten)]
    pub extra: HashMap<String, serde_json::Value>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    Global,
    Rule,
    Direct,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "lowercase")]
pub enum LogLevel {
    Trace,
    Debug,
    Info,
    Warn,
    Error,
    Fatal,
}

/// Protocol name
pub const PROTOCOL_NAME: &str = "clash";
/// Configuration file extension
pub const CONFIG_EXT: &str = "yaml";

/// Generate default Clash configuration template
pub fn generate_default_template() -> String {
    default_template::generate()
}
