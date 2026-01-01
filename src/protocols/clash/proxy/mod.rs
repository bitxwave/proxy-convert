pub mod http;
pub mod shadowsocks;
pub mod shadowsocks_r;
pub mod snell;
pub mod socks5;
pub mod trojan;
pub mod vmess;

use serde::{Deserialize, Serialize};

pub use http::Http;
pub use shadowsocks::Shadowsocks;
pub use shadowsocks_r::ShadowsocksR;
pub use snell::Snell;
pub use socks5::Socks5;
pub use trojan::Trojan;
pub use vmess::Vmess;

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum Proxy {
    Ss(Shadowsocks),
    Ssr(ShadowsocksR),
    Vmess(Vmess),
    Socks5(Socks5),
    Http(Http),
    Snell(Snell),
    Trojan(Trojan),
}

impl Proxy {
    pub fn name(&self) -> &str {
        match self {
            Proxy::Ss(ss) => &ss.name,
            Proxy::Ssr(ssr) => &ssr.name,
            Proxy::Vmess(vmess) => &vmess.name,
            Proxy::Socks5(socks5) => &socks5.name,
            Proxy::Http(http) => &http.name,
            Proxy::Snell(snell) => &snell.name,
            Proxy::Trojan(trojan) => &trojan.name,
        }
    }
}
