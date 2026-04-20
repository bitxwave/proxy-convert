//! Sing-box ProtocolFormat implementation.

use crate::core::error::{ConvertError, Result};
use crate::protocols::protocol_format::ProtocolFormat;
use crate::utils::source::parser::Config;

/// Sing-box format descriptor.
pub struct SingboxFormat;

impl ProtocolFormat for SingboxFormat {
    fn name(&self) -> &'static str {
        "singbox"
    }

    fn aliases(&self) -> &'static [&'static str] {
        &["sing-box"]
    }

    fn config_ext(&self) -> &'static str {
        "json"
    }

    fn default_filename(&self) -> &'static str {
        "config.json"
    }

    fn default_template(&self) -> String {
        super::generate_default_template()
    }

    fn validate(&self, content: &str) -> Result<()> {
        let config: serde_json::Value =
            serde_json::from_str(content).map_err(|e| ConvertError::JsonParseError(e))?;

        if config.get("outbounds").is_none() {
            return Err(ConvertError::ConfigValidationError(
                "Missing required field 'outbounds' for Sing-box config".to_string(),
            ));
        }

        tracing::info!("Sing-box config structure is valid");
        Ok(())
    }

    fn parse_config(&self, content: &str) -> Result<Config> {
        let config =
            crate::utils::source::loader::SourceLoader::parse_singbox_config(content)?;
        Ok(Config::SingBox(config))
    }
}
