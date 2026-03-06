pub mod base;
pub mod direct;
pub mod mixed;
pub mod socks;
pub mod http;
pub mod shadowsocks;
pub mod vmess;
pub mod trojan;
pub mod naive;
pub mod hysteria;
pub mod shadowtls;
pub mod tuic;
pub mod hysteria2;
pub mod vless;
pub mod anytls;
pub mod tun;
pub mod redirect;
pub mod tproxy;

use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum Inbound {
    Direct(direct::Direct),
    Mixed(mixed::Mixed),
    Socks(socks::Socks),
    Http(http::HTTP),
    Shadowsocks(shadowsocks::Shadowsocks),
    Vmess(vmess::VMess),
    Trojan(trojan::Trojan),
    Naive(naive::Naive),
    Hysteria(hysteria::Hysteria),
    Shadowtls(shadowtls::ShadowTLS),
    Tuic(tuic::TUIC),
    Hysteria2(hysteria2::Hysteria2),
    Vless(vless::VLESS),
    Anytls(anytls::AnyTLS),
    Tun(tun::Tun),
    Redirect(redirect::Redirect),
    Tproxy(tproxy::TProxy),
}
