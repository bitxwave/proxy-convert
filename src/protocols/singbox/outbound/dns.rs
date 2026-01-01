use serde::{Deserialize, Serialize};

#[derive(Default, Serialize, Deserialize, Debug, Clone)]
pub struct Dns {
    pub tag: String,
}
