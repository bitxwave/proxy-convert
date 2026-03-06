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
    enabled: Option<bool>,
    pq_signature_schemes_enabled: Option<bool>,
    dynamic_record_sizing_disabled: Option<bool>,
    key: Option<Vec<String>>,
    key_path: Option<String>,
}

#[skip_serializing_none]
#[derive(Default, Serialize, Deserialize, Debug, Clone)]
pub struct Reality {
    enabled: Option<bool>,
    handshake: Option<RealityHandshake>,
    public_key: Option<String>,
    private_key: Option<String>,
    short_id: Option<SingleOrMultipleValue<String>>,
    max_time_difference: Option<String>,
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
    pub insecure: Option<bool>,
    pub server_name: Option<String>,
    pub certificate: Option<SingleOrMultipleValue<String>>,
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
    pub early_data_size: Option<u32>,
    pub session_cache_size: Option<u32>,
    pub session_cache_timeout: Option<u64>,
    pub client_certificate: Option<ClientCertificateConfig>,
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

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ClientCertificateConfig {
    pub certificate_path: Option<String>,
    pub key_path: Option<String>,
    pub password: Option<String>,
    pub ocsp_stapling: Option<u64>,
}