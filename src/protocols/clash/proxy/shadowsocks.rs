// use std::collections::HashMap; // 暂时未使用

use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;

#[skip_serializing_none]
#[derive(Default, Serialize, Deserialize, Debug)]
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

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "kebab-case")]
pub enum Plugin {
    Obfs,
    V2rayPlugin,
}

// 这些结构体暂时未使用，但保留以备将来扩展
// #[derive(Serialize, Deserialize, Debug)]
// #[serde(tag = "mode")]
// pub enum PluginOpts {
//     Tls(Tls),
//     Http(Http),
//     Websocket(Websocket),
// }

// #[derive(Serialize, Deserialize, Debug)]
// pub struct Tls {
//     pub host: String,
// }

// #[derive(Serialize, Deserialize, Debug)]
// pub struct Http {
//     pub host: String,
// }

// #[derive(Serialize, Deserialize, Debug)]
// pub struct Websocket {
//     pub tls: bool,
//     #[serde(rename = "skip-cert-verify")]
//     pub skip_cert_verify: bool,
//     pub host: String,
//     pub path: String,
//     pub mux: bool,
//     pub headers: HashMap<String, String>,
// }
