use crate::protocols::singbox::common::base::DialParams;
use serde::{ Deserialize, Serialize };
use serde_with::skip_serializing_none;

#[skip_serializing_none]
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Direct {
    pub tag: String,
    
    #[serde(flatten)]
    pub dial_params: DialParams,
}