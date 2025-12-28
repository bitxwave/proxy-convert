pub mod base;
pub mod direct;
pub mod dns;
pub mod http;
pub mod hysteria;
pub mod hysteria2;
pub mod selector;
pub mod shadowsocks;
pub mod shadowtls;
pub mod socks;
pub mod ssh;
pub mod tor;
pub mod trojan;
pub mod tuic;
pub mod urltest;
pub mod vless;
pub mod vmess;
pub mod wireguard;

use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum Outbound {
    Direct(direct::Direct),
    Socks(socks::Socks),
    Http(http::Http),
    Shadowsocks(shadowsocks::Shadowsocks),
    Vmess(vmess::Vmess),
    Trojan(trojan::Trojan),
    Wireguard(wireguard::Wireguard),
    Hysteria(hysteria::Hysteria),
    Vless(vless::Vless),
    Shadowtls(shadowtls::Shadowtls),
    Tuic(tuic::Tuic),
    Hysteria2(hysteria2::Hysteria2),
    Tor(tor::Tor),
    Ssh(ssh::Ssh),
    Dns(dns::Dns),
    Selector(selector::Selector),
    Urltest(urltest::Urltest),
}
