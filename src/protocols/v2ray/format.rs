//! V2Ray ProtocolFormat implementation.

use crate::core::error::{ConvertError, Result};
use crate::protocols::protocol_format::ProtocolFormat;
use crate::utils::source::parser::Config;

/// V2Ray format descriptor.
pub struct V2RayFormat;

impl ProtocolFormat for V2RayFormat {
    fn name(&self) -> &'static str {
        "v2ray"
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
                "Missing required field 'outbounds' for V2Ray config".to_string(),
            ));
        }

        tracing::info!("V2Ray config structure is valid");
        Ok(())
    }

    fn parse_config(&self, content: &str) -> Result<Config> {
        let config: super::Config =
            crate::utils::parse_helpers::from_json_or_yaml(content)?;
        Ok(Config::V2Ray(config))
    }
}
