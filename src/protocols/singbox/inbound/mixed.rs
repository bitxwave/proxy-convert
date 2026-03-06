use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;
use crate::protocols::singbox::common::base::ListenParams;
use super::base::User;

#[skip_serializing_none]
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Mixed {
    pub tag: Option<String>,

    #[serde(flatten)]
    pub listen_params: ListenParams,

    pub users: Option<Vec<User>>,
    pub set_system_proxy: Option<bool>,
}