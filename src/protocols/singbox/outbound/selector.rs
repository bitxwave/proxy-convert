use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;

#[skip_serializing_none]
#[derive(Default, Serialize, Deserialize, Debug)]
pub struct Selector {
    pub tag: String,
    pub interrupt_exist_connections: Option<bool>,
    pub default: Option<String>,
    pub outbounds: Vec<String>,
}
