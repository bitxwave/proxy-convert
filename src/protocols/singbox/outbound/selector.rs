use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;

#[skip_serializing_none]
#[derive(Default, Serialize, Deserialize, Debug, Clone)]
pub struct Selector {
    pub tag: String,
    pub outbounds: Vec<String>,
    pub default: Option<String>,
    pub interrupt_exist_connections: Option<bool>,
}
