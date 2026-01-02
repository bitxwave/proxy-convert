use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;
use super::base::User;
use crate::protocols::singbox::common::base::ListenParams;

#[skip_serializing_none]
#[derive(Default, Serialize, Deserialize, Debug, Clone)]
pub struct Socks {
    pub tag: Option<String>,
    
    #[serde(flatten)]
    pub listen_params: ListenParams,

    pub users: Option<Vec<User>>,
}
