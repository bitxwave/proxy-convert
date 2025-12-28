use super::base::{SingleOrMultipleValue, Strategy};
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;

#[derive(Serialize, Deserialize, Debug)]
#[serde(untagged)]
pub enum Tls {
    Inbound(Inbound),
    Outbound(Outbound),
}

#[skip_serializing_none]
#[derive(Default, Serialize, Deserialize, Debug)]
pub struct Inbound {
    enabled: Option<bool>,
    server_name: Option<String>,
    alpn: Option<Vec<String>>,
    min_version: Option<String>,
    max_version: Option<String>,
    cipher_suites: Option<Vec<String>>,
    certificate: Option<Vec<String>>,
    certificate_path: Option<String>,
    key: Option<Vec<String>>,
    key_path: Option<String>,
    acme: Option<ACME>,
    ech: Option<Ech>,
    reality: Option<Reality>,
}

#[skip_serializing_none]
#[derive(Default, Serialize, Deserialize, Debug)]
pub struct ACME {
    domain: Option<Vec<String>>,
    data_directory: Option<String>,
    default_server_name: Option<String>,
    email: Option<String>,
    provider: Option<String>,
    disable_http_challenge: Option<bool>,
    disable_tls_alpn_challenge: Option<bool>,
    alternative_http_port: Option<u16>,
    alternative_tls_port: Option<u16>,
    external_account: Option<ExternalAccount>,
    dns01_challenge: Option<Dns01Challenge>,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(tag = "provider", rename_all = "lowercase")]
pub enum Dns01Challenge {
    Alidns {
        access_key_id: String,
        access_key_secret: String,
        region_id: String,
    },
    Cloudflare {
        api_token: String,
    },
}

#[skip_serializing_none]
#[derive(Default, Serialize, Deserialize, Debug)]
pub struct ExternalAccount {
    key_id: Option<String>,
    mac_key: Option<String>,
}

#[skip_serializing_none]
#[derive(Default, Serialize, Deserialize, Debug)]
pub struct Ech {
    enabled: Option<bool>,
    pq_signature_schemes_enabled: Option<bool>,
    dynamic_record_sizing_disabled: Option<bool>,
    key: Option<Vec<String>>,
    key_path: Option<String>,
}

#[skip_serializing_none]
#[derive(Default, Serialize, Deserialize, Debug)]
pub struct Reality {
    enabled: Option<bool>,
    handshake: Option<RealityHandshake>,
    public_key: Option<String>,
    private_key: Option<String>,
    short_id: Option<SingleOrMultipleValue<String>>,
    max_time_difference: Option<String>,
}

#[skip_serializing_none]
#[derive(Default, Serialize, Deserialize, Debug)]
pub struct RealityHandshake {
    server: Option<String>,
    server_port: Option<u16>,
    detour: Option<String>,
    bind_interface: Option<String>,
    inet4_bind_address: Option<String>,
    inet6_bind_address: Option<String>,
    routing_mark: Option<usize>,
    reuse_addr: Option<bool>,
    connect_timeout: Option<String>,
    tcp_fast_open: Option<bool>,
    tcp_multi_path: Option<bool>,
    udp_fragment: Option<bool>,
    domain_strategy: Option<Strategy>,
    fallback_delay: Option<String>,
}

#[skip_serializing_none]
#[derive(Default, Serialize, Deserialize, Debug)]
pub struct Outbound {
    enabled: Option<bool>,
    disable_sni: Option<bool>,
    server_name: Option<String>,
    insecure: Option<bool>,
    alpn: Option<Vec<String>>,
    min_version: Option<String>,
    max_version: Option<String>,
    cipher_suites: Option<Vec<String>>,
    certificate: Option<Vec<String>>,
    certificate_path: Option<String>,
    ech: Option<Ech>,
    utls: Option<OutboundUtils>,
    reality: Option<Reality>,
}

#[skip_serializing_none]
#[derive(Default, Serialize, Deserialize, Debug)]
pub struct OutboundUtils {
    enabled: Option<bool>,
    fingerprint: Option<String>,
}
