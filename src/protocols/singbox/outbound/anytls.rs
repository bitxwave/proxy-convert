use crate::protocols::singbox::common::{ base::DialParams, tls };
use serde::{ Deserialize, Serialize };
use serde_with::skip_serializing_none;

/// sing-box AnyTLS outbound. See https://sing-box.sagernet.org/configuration/outbound/anytls/
///
/// Required: `server`, `server_port`, `password`, `tls`.
/// Optional idle-session knobs default to "30s" / 0 server-side; we keep them
/// optional so we don't fabricate values during conversion.
#[skip_serializing_none]
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AnyTLS {
    pub tag: String,
    pub server: String,
    pub server_port: u16,
    pub password: String,
    pub idle_session_check_interval: Option<String>,
    pub idle_session_timeout: Option<String>,
    pub min_idle_session: Option<u32>,
    pub tls: tls::Outbound,

    #[serde(flatten)]
    pub dial_params: DialParams,
}
