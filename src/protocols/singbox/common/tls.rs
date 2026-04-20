use super::base::{SingleOrMultipleValue, Strategy};
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(untagged)]
pub enum Tls {
    Inbound(Inbound),
    Outbound(Outbound),
}


#[skip_serializing_none]
#[derive(Default, Serialize, Deserialize, Debug, Clone)]
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

#[derive(Serialize, Deserialize, Debug, Clone)]
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
#[derive(Default, Serialize, Deserialize, Debug, Clone)]
pub struct ExternalAccount {
    key_id: Option<String>,
    mac_key: Option<String>,
}

#[skip_serializing_none]
#[derive(Default, Serialize, Deserialize, Debug, Clone)]
pub struct Ech {
    pub enabled: Option<bool>,
    pub config: Option<SingleOrMultipleValue<String>>,
    pub config_path: Option<String>,
    pub query_server_name: Option<String>,
    // deprecated fields kept for backwards compat
    pub pq_signature_schemes_enabled: Option<bool>,
    pub dynamic_record_sizing_disabled: Option<bool>,
    pub key: Option<Vec<String>>,
    pub key_path: Option<String>,
}

#[skip_serializing_none]
#[derive(Default, Serialize, Deserialize, Debug, Clone)]
pub struct Reality {
    pub enabled: Option<bool>,
    pub public_key: Option<String>,
    pub short_id: Option<SingleOrMultipleValue<String>>,
    // server-side fields
    pub handshake: Option<RealityHandshake>,
    pub private_key: Option<String>,
    pub max_time_difference: Option<String>,
}

#[skip_serializing_none]
#[derive(Default, Serialize, Deserialize, Debug, Clone)]
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
#[derive(Default, Serialize, Deserialize, Debug, Clone)]
pub struct OutboundUtils {
    enabled: Option<bool>,
    fingerprint: Option<String>,
}

#[skip_serializing_none]
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Inbound {
    pub enabled: Option<bool>,
    pub certificate: Option<SingleOrMultipleValue<String>>,
    pub key: Option<SingleOrMultipleValue<String>>,
    pub key_password: Option<String>,
    pub fingerprint: Option<TlsFingerprint>,
    pub alpn: Option<Vec<String>>,
    pub alpn_mode: Option<AlpnMode>,
    pub min_version: Option<String>,
    pub max_version: Option<String>,
    pub session_ticket: Option<bool>,
    pub curves: Option<Vec<String>>,
    pub signature_algorithms: Option<String>,
    pub key_share_mode: Option<String>,
    pub only_grease: Option<bool>,
    pub force_ciphersuites: Option<Vec<String>>,
    pub session_cache_size: Option<u32>,
    pub session_cache_timeout: Option<u64>,
    pub client_auth: Option<bool>,
    pub client_ca: Option<SingleOrMultipleValue<String>>,
}

#[skip_serializing_none]
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Outbound {
    pub enabled: Option<bool>,
    pub engine: Option<String>,
    pub disable_sni: Option<bool>,
    pub server_name: Option<String>,
    pub insecure: Option<bool>,
    pub alpn: Option<Vec<String>>,
    pub alpn_mode: Option<AlpnMode>,
    pub min_version: Option<String>,
    pub max_version: Option<String>,
    pub cipher_suites: Option<Vec<String>>,
    pub curve_preferences: Option<Vec<String>>,
    pub certificate: Option<SingleOrMultipleValue<String>>,
    pub certificate_path: Option<String>,
    pub certificate_public_key_sha256: Option<Vec<String>>,
    pub client_certificate: Option<SingleOrMultipleValue<String>>,
    pub client_certificate_path: Option<String>,
    pub client_key: Option<SingleOrMultipleValue<String>>,
    pub client_key_path: Option<String>,
    pub fragment: Option<bool>,
    pub fragment_fallback_delay: Option<String>,
    pub record_fragment: Option<bool>,
    pub spoof: Option<String>,
    pub spoof_method: Option<String>,
    pub kernel_tx: Option<bool>,
    pub kernel_rx: Option<bool>,
    pub handshake_timeout: Option<String>,
    pub ech: Option<Ech>,
    pub utls: Option<Utls>,
    pub reality: Option<Reality>,
    // deprecated fields kept for backwards compatibility during deserialization
    pub fingerprint: Option<TlsFingerprint>,
    pub session_ticket: Option<bool>,
    pub curves: Option<Vec<String>>,
    pub signature_algorithms: Option<String>,
    pub key_share_mode: Option<String>,
    pub only_grease: Option<bool>,
    pub force_ciphersuites: Option<Vec<String>>,
    pub early_data_size: Option<u32>,
    pub session_cache_size: Option<u32>,
    pub session_cache_timeout: Option<u64>,
}

#[skip_serializing_none]
#[derive(Default, Serialize, Deserialize, Debug, Clone)]
pub struct Utls {
    pub enabled: Option<bool>,
    pub fingerprint: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum TlsFingerprint {
    Chrome,
    Firefox,
    Safari,
    Ios,
    Android,
    Edge,
    Random,
    Randomized,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AlpnMode {
    Auto,
    Strict,
}

