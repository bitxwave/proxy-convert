use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;
use std::collections::HashMap;

#[skip_serializing_none]
#[derive(Default, Serialize, Deserialize, Debug, Clone)]
pub struct Shadowsocks {
    pub name: String,
    pub server: String,
    pub port: u16,
    pub password: String,
    pub cipher: String,
    pub udp: Option<bool>,
    #[serde(rename = "interface-name")]
    pub interface_name: Option<String>,
    #[serde(rename = "routing-mark")]
    pub routing_mark: Option<usize>,
    pub plugin: Option<Plugin>,
    #[serde(rename = "plugin-opts")]
    pub plugin_opts: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "kebab-case")]
pub enum Plugin {
    Obfs,
    V2rayPlugin,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(tag = "mode")]
pub enum PluginOpts {
    Tls(Tls),
    Http(Http),
    Websocket(Websocket),
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Tls {
    pub host: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Http {
    pub host: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Websocket {
    pub tls: bool,
    #[serde(rename = "skip-cert-verify")]
    pub skip_cert_verify: bool,
    pub host: String,
    pub path: String,
    pub mux: bool,
    pub headers: HashMap<String, String>,
}
