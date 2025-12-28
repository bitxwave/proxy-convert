use serde::{Deserialize, Serialize};

#[derive(Default, Serialize, Deserialize, Debug)]
pub struct User {
    pub username: String,
    pub password: String,
}
