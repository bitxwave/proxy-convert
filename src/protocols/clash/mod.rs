//! Clash Protocol Support Module

pub mod dns;
pub mod proxy;
pub mod proxy_group;
pub mod template_processor;

use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "kebab-case")]
pub struct Config {
    pub mixed_port: Option<u16>,
    pub allow_lan: Option<bool>,
    pub bind_address: Option<String>,
    pub mode: Option<Mode>,
    pub log_level: Option<LogLevel>,
    pub external_controller: Option<String>,
    pub dns: Option<dns::DNS>,
    pub proxies: Vec<proxy::Proxy>,
    pub proxy_groups: Vec<proxy_group::ProxyGroup>,
    pub rules: Vec<String>,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    Global,
    Rule,
    Direct,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "lowercase")]
pub enum LogLevel {
    Trace,
    Debug,
    Info,
    Warn,
    Error,
    Fatal,
}
