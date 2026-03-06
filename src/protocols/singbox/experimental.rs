use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;

#[skip_serializing_none]
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Experimental {
    cache_file: Option<CacheFile>,
    clash_api: Option<ClashApi>,
    v2ray_api: Option<V2rayApi>,
}

#[skip_serializing_none]
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct CacheFile {
    pub enabled: Option<bool>,
    pub path: Option<String>,
    pub cache_id: Option<String>,
    pub store_fakeip: Option<bool>,
    pub store_rdrc: Option<bool>,
    pub rdrc_timeout: Option<String>,
}

#[skip_serializing_none]
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ClashApi {
    pub external_controller: Option<String>,
    pub external_ui: Option<String>,
    pub external_ui_download_url: Option<String>,
    pub external_ui_download_detour: Option<String>,
    pub secret: Option<String>,
    pub default_mode: Option<String>,
    pub access_control_allow_origin: Option<Vec<String>>,
    pub access_control_allow_private_network: Option<bool>,
}

#[skip_serializing_none]
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct V2rayApi {
    pub listen: Option<String>,
    pub stats: Option<V2rayStats>,
}

#[skip_serializing_none]
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct V2rayStats {
    pub enabled: Option<bool>,
    pub inbounds: Option<Vec<String>>,
    pub outbounds: Option<Vec<String>>,
    pub users: Option<Vec<String>>,
}
