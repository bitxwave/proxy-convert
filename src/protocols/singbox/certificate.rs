use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;

#[skip_serializing_none]
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Certificate {
    pub store: Option<StoreType>,
    pub certificate: Option<Vec<String>>,
    pub certificate_path: Option<Vec<String>>,
    pub certificate_directory_path: Option<Vec<String>>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "lowercase")]
pub enum StoreType {
    System,
    Mozilla,
    Chrome,
    None,
}