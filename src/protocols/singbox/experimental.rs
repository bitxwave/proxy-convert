use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;

#[skip_serializing_none]
#[derive(Default, Serialize, Deserialize, Debug)]
pub struct Experimental {
    cache_file: Option<CacheFile>,
    clash_api: Option<ClashApi>,
    v2ray_api: Option<V2rayApi>,
}

#[skip_serializing_none]
#[derive(Default, Serialize, Deserialize, Debug)]
pub struct CacheFile {
    enabled: Option<bool>,
    path: Option<String>,
    cache_id: Option<String>,
    store_fakeip: Option<bool>,
    store_rdrc: Option<bool>,
    rdrc_timeout: Option<String>,
}

#[skip_serializing_none]
#[derive(Default, Serialize, Deserialize, Debug)]
pub struct ClashApi {
    external_controller: Option<String>,
    external_ui: Option<String>,
    external_ui_download_url: Option<String>,
    external_ui_download_detour: Option<String>,
    secret: Option<String>,
    default_mode: Option<String>,
}

#[skip_serializing_none]
#[derive(Default, Serialize, Deserialize, Debug)]
pub struct V2rayApi {
    listen: Option<String>,
    stats: Option<V2rayStats>,
}

#[skip_serializing_none]
#[derive(Default, Serialize, Deserialize, Debug)]
pub struct V2rayStats {
    enabled: Option<String>,
    inbounds: Option<Vec<String>>,
    outbounds: Option<Vec<String>>,
    users: Option<Vec<String>>,
}
