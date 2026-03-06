use crate::protocols::singbox::common::base::{ Network, ListenParams };
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;

#[skip_serializing_none]
#[derive(Default, Serialize, Deserialize, Debug, Clone)]
pub struct TProxy {
    pub tag: Option<String>,

    #[serde(flatten)]
    pub listen_params: ListenParams,

    pub network: Option<Network>,
}
