pub mod base;
pub mod direct;
pub mod socks;
pub mod http;
pub mod shadowsocks;
pub mod vmess;
pub mod trojan;
pub mod naive;
pub mod hysteria;
pub mod shadowtls;
pub mod vless;
pub mod tuic;
pub mod hysteria2;
pub mod anytls;
pub mod tor;
pub mod ssh;
pub mod selector;
pub mod urltest;


use serde::{ Deserialize, Serialize };

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Outbound {
    Direct(direct::Direct),
    Socks(socks::Socks),
    Http(http::HTTP),
    Shadowsocks(shadowsocks::Shadowsocks),
    Vmess(vmess::VMess),
    Trojan(trojan::Trojan),
    Naive(naive::Naive),
    Hysteria(hysteria::Hysteria),
    Shadowtls(shadowtls::ShadowTLS),
    Vless(vless::VLESS),
    Tuic(tuic::TUIC),
    Hysteria2(hysteria2::Hysteria2),
    Anytls(anytls::AnyTLS),
    Tor(tor::Tor),
    Ssh(ssh::SSH),
    Selector(selector::Selector),
    Urltest(urltest::Urltest),
}
