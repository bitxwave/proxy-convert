//! Clash ProtocolFormat implementation.

use crate::core::error::{ConvertError, Result};
use crate::protocols::protocol_format::ProtocolFormat;
use crate::utils::source::parser::Config;

/// Clash format descriptor.
pub struct ClashFormat;

impl ProtocolFormat for ClashFormat {
    fn name(&self) -> &'static str {
        "clash"
    }

    fn config_ext(&self) -> &'static str {
        "yaml"
    }

    fn default_filename(&self) -> &'static str {
        "config.yaml"
    }

    fn default_template(&self) -> String {
        super::generate_default_template()
    }

    fn validate(&self, content: &str) -> Result<()> {
        let config: serde_json::Value = serde_yaml::from_str(content).map_err(|e| {
            ConvertError::ConfigValidationError(format!("YAML parse error: {}", e))
        })?;

        if config.get("proxies").is_none() && config.get("proxy-providers").is_none() {
            return Err(ConvertError::ConfigValidationError(
                "Missing required field 'proxies' or 'proxy-providers' for Clash config"
                    .to_string(),
            ));
        }

        tracing::info!("Clash config structure is valid");
        Ok(())
    }

    fn parse_config(&self, content: &str) -> Result<Config> {
        let config: super::Config =
            crate::utils::parse_helpers::from_json_or_yaml(content)?;
        Ok(Config::Clash(config))
    }
}
