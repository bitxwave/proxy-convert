pub mod anytls;
pub mod common;
pub mod http;
pub mod hysteria;
pub mod hysteria2;
pub mod shadowsocks;
pub mod shadowsocks_r;
pub mod snell;
pub mod socks5;
pub mod trojan;
pub mod tuic;
pub mod vless;
pub mod vmess;
pub mod wireguard;

use serde::{Deserialize, Serialize};

pub use anytls::AnyTls;
pub use http::Http;
pub use hysteria::Hysteria;
pub use hysteria2::Hysteria2;
pub use shadowsocks::Shadowsocks;
pub use shadowsocks_r::ShadowsocksR;
pub use snell::Snell;
pub use socks5::Socks5;
pub use trojan::Trojan;
pub use tuic::Tuic;
pub use vless::Vless;
pub use vmess::Vmess;
pub use wireguard::WireGuard;

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum Proxy {
    Ss(Shadowsocks),
    Ssr(ShadowsocksR),
    Vmess(Vmess),
    Vless(Vless),
    Socks5(Socks5),
    Http(Http),
    Snell(Snell),
    Trojan(Trojan),
    Anytls(AnyTls),
    Hysteria(Hysteria),
    Hysteria2(Hysteria2),
    Tuic(Tuic),
    Wireguard(WireGuard),
}

impl Proxy {
    pub fn name(&self) -> &str {
        match self {
            Proxy::Ss(ss) => &ss.name,
            Proxy::Ssr(ssr) => &ssr.name,
            Proxy::Vmess(vmess) => &vmess.name,
            Proxy::Vless(vless) => &vless.name,
            Proxy::Socks5(socks5) => &socks5.name,
            Proxy::Http(http) => &http.name,
            Proxy::Snell(snell) => &snell.name,
            Proxy::Trojan(trojan) => &trojan.name,
            Proxy::Anytls(anytls) => &anytls.name,
            Proxy::Hysteria(h) => &h.name,
            Proxy::Hysteria2(h2) => &h2.name,
            Proxy::Tuic(t) => &t.name,
            Proxy::Wireguard(w) => &w.name,
        }
    }
}
