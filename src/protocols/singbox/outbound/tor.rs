use crate::protocols::singbox::common::base::DialParams;
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;

#[skip_serializing_none]
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Tor {
    pub tag: String,
    pub executable_path: Option<String>,
    pub extra_args: Option<Vec<String>>,
    pub data_directory: Option<String>,
    pub torrc: Option<Torrc>,

    #[serde(flatten)]
    pub dial_params: DialParams,
}

#[skip_serializing_none]
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Torrc {
    #[serde(rename = "ClientOnly")]
    pub client_only: TorClientOnly,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(into = "u8", try_from = "u8")]
pub enum TorClientOnly {
    #[default]
    AllowRelay = 0,
    ForceClient = 1,
}

impl From<TorClientOnly> for u8 {
    fn from(val: TorClientOnly) -> Self {
        val as u8
    }
}

impl TryFrom<u8> for TorClientOnly {
    type Error = String;

    fn try_from(val: u8) -> Result<Self, Self::Error> {
        match val {
            0 => Ok(Self::AllowRelay),
            1 => Ok(Self::ForceClient),
            _ => Err(format!("invalid TorClientOnly value: {}, must be 0 or 1", val)),
        }
    }
}