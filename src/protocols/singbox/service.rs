use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;
use crate::protocols::singbox::common::{base::{DialParams, ListenParams}, tls};
use indexmap::IndexMap;

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(tag = "type", rename_all = "kebab-case")]
pub enum Service {
    Ccm(CCM),
    Derp(DERP),
    Ocm(OCM),
    Resolved(Resolved),
    SsmApi(SSMAPI),
}

#[skip_serializing_none]
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct CCM {
  #[serde(flatten)]
  pub listen_params: ListenParams,

  credential_path: Option<String>,
  usages_path: Option<String>,
  users: Option<Vec<User>>,
  headers: Option<IndexMap<String, String>>,
  detour: Option<String>,
  tls: Option<tls::Tls>,
}

#[skip_serializing_none]
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct User {
    pub username: String,
    pub password: String,
}

#[skip_serializing_none]
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DERP {
  #[serde(flatten)]
  pub listen_params: ListenParams,

  pub tls: Option<tls::Tls>,
  pub config_path: String,
  pub verify_client_endpoint: Option<Vec<String>>,
  pub verify_client_url: Option<Vec<VerifyClientUrl>>,
  pub home: Option<String>,
  pub mesh_with: Option<Vec<MeshWith>>,
  pub mesh_psk: Option<String>,
  pub mesh_psk_file: Option<String>,
  pub stun: Option<Stun>,
}

#[skip_serializing_none]
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct VerifyClientUrl {
  pub url: String,

  #[serde(flatten)]
  pub dial_params: DialParams,
}

#[skip_serializing_none]
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct MeshWith {
  pub server: String,
  pub server_port: u16,
  pub host: Option<String>,
  pub tls: Option<tls::Tls>,

  #[serde(flatten)]
  pub listen_params: ListenParams,
}

#[skip_serializing_none]
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Stun {
  pub enable: Option<bool>,

  #[serde(flatten)]
  pub listen_params: ListenParams,
}

#[skip_serializing_none]
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct OCM {
  #[serde(flatten)]
  pub listen_params: ListenParams,

  pub credential_path: Option<String>,
  pub usages_path: Option<String>,
  pub users: Option<Vec<OCMUser>>,
  pub headers: Option<IndexMap<String, String>>,
  pub detour: Option<String>,
  pub tls: Option<tls::Tls>,
}

#[skip_serializing_none]
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Resolved {
  #[serde(flatten)]
  pub listen_params: ListenParams,
}

#[skip_serializing_none]
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SSMAPI {
  #[serde(flatten)]
  pub listen_params: ListenParams,


  pub servers: IndexMap<String, String>,
  pub cache_path: Option<String>,
  pub tls: Option<tls::Tls>,
}

#[skip_serializing_none]
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct OCMUser {
  pub name: String,
  pub token: String,
}

