use serde::{Deserialize, Serialize};

#[derive(Default, Serialize, Deserialize, Debug, Clone)]
pub struct User {
    pub username: String,
    pub password: String,
}
