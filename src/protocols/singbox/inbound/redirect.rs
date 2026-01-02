use crate::protocols::singbox::common::base::ListenParams;
use serde::{ Deserialize, Serialize };
use serde_with::skip_serializing_none;

#[skip_serializing_none]
#[derive(Default, Serialize, Deserialize, Debug, Clone)]
pub struct Redirect {
    pub tag: Option<String>,

    #[serde(flatten)]
    pub listen_params: ListenParams,
}
