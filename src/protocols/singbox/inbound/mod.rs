pub mod base;
pub mod direct;
pub mod http;
pub mod hysteria;
pub mod hysteria2;
pub mod mixed;
pub mod naive;
pub mod redirect;
pub mod shadowsocks;
pub mod shadowtls;
pub mod socks;
pub mod tproxy;
pub mod trojan;
pub mod tuic;
pub mod tun;
pub mod vless;
pub mod vmess;

use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum Inbound {
    Direct(direct::Direct),
    Mixed(mixed::Mixed),
    Socks(socks::Socks),
    Http(http::Http),
    Shadowsocks(shadowsocks::Shadowsocks),
    Vmess(vmess::Vmess),
    Trojan(trojan::Trojan),
    Naive(naive::Naive),
    Hysteria(hysteria::Hysteria),
    Shadowtls(shadowtls::Shadowtls),
    Vless(vless::Vless),
    Tuic(tuic::Tuic),
    Hysteria2(hysteria2::Hysteria2),
    Tun(tun::Tun),
    Redirect(redirect::Redirect),
    Tproxy(tproxy::Tproxy),
}
