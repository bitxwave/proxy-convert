use crate::core::error::{ConvertError, Result};

/// Try to deserialize content as JSON first, then YAML.
pub fn from_json_or_yaml<T: serde::de::DeserializeOwned>(content: &str) -> Result<T> {
    serde_json::from_str::<T>(content).or_else(|_| {
        serde_yaml::from_str::<T>(content).map_err(|e| {
            ConvertError::ConfigValidationError(format!(
                "Failed to parse as JSON or YAML: {}",
                e
            ))
        })
    })
}

/// Try to parse content into serde_json::Value (JSON first, then YAML).
pub fn to_json_value(content: &str) -> Result<serde_json::Value> {
    from_json_or_yaml(content)
}
