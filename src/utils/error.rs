use thiserror::Error;

#[derive(Error, Debug)]
pub enum ConvertError {
    #[error("JSON parse error: {0}")]
    JsonParseError(#[from] serde_json::Error),

    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("File not found: {0}")]
    FileNotFound(String),

    #[error("Template error: {0}")]
    TemplateError(String),

    #[error("Source error: {0}")]
    SourceError(String),

    #[error("Network error: {0}")]
    NetworkError(String),

    #[error("Config error: {0}")]
    ConfigValidationError(String),
}

pub type Result<T> = std::result::Result<T, ConvertError>;

impl ConvertError {
    pub fn file_not_found(path: &str) -> Self {
        Self::FileNotFound(path.to_string())
    }

    pub fn template_error(msg: &str) -> Self {
        Self::TemplateError(msg.to_string())
    }

    pub fn source_error(msg: &str) -> Self {
        Self::SourceError(msg.to_string())
    }

    pub fn network_error(msg: &str) -> Self {
        Self::NetworkError(msg.to_string())
    }

    /// Format error for display
    pub fn format_error(&self) -> String {
        match self {
            ConvertError::FileNotFound(path) => {
                format!("File not found: {}\n  Please check if the file path is correct.", path)
            }
            ConvertError::IoError(e) => {
                format!("IO error: {}", e)
            }
            ConvertError::JsonParseError(e) => {
                format!("JSON parse error: {}\n  Please check if the file format is valid JSON.", e)
            }
            ConvertError::TemplateError(msg) => {
                format!("Template error: {}", msg)
            }
            ConvertError::SourceError(msg) => {
                format!("Source error: {}", msg)
            }
            ConvertError::NetworkError(msg) => {
                format!("Network error: {}\n  Please check your network connection.", msg)
            }
            ConvertError::ConfigValidationError(msg) => {
                format!("Config error: {}", msg)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_convert_error_display() {
        let error = ConvertError::ConfigValidationError("Test error".to_string());
        let error_string = format!("{}", error);
        assert!(error_string.contains("Config error"));
        assert!(error_string.contains("Test error"));
    }

    #[test]
    fn test_convert_error_debug() {
        let error = ConvertError::ConfigValidationError("Test error".to_string());
        let debug_string = format!("{:?}", error);
        assert!(debug_string.contains("ConfigValidationError"));
    }

    #[test]
    fn test_file_not_found_error() {
        let error = ConvertError::file_not_found("/path/to/file");
        let formatted = error.format_error();
        assert!(formatted.contains("File not found"));
        assert!(formatted.contains("/path/to/file"));
    }

    #[test]
    fn test_convert_error_from_serde_json() {
        let json_error = serde_json::from_str::<serde_json::Value>("invalid json");
        assert!(json_error.is_err());

        if let Err(json_err) = json_error {
            let convert_error: ConvertError = json_err.into();
            match convert_error {
                ConvertError::JsonParseError(_) => {}
                _ => panic!("Expected JsonParseError"),
            }
        }
    }

    #[test]
    fn test_convert_error_from_io() {
        let io_error = std::fs::read_to_string("/nonexistent/file");
        assert!(io_error.is_err());

        if let Err(io_err) = io_error {
            let convert_error: ConvertError = io_err.into();
            match convert_error {
                ConvertError::IoError(_) => {}
                _ => panic!("Expected IoError"),
            }
        }
    }

    #[test]
    fn test_result_type_alias() {
        fn test_function() -> Result<String> {
            Ok("test".to_string())
        }

        fn test_error_function() -> Result<String> {
            Err(ConvertError::ConfigValidationError("test error".to_string()))
        }

        assert!(test_function().is_ok());
        assert!(test_error_function().is_err());
    }

    #[test]
    fn test_format_error() {
        let error = ConvertError::file_not_found("test.json");
        let formatted = error.format_error();
        assert!(formatted.contains("File not found"));
        assert!(formatted.contains("test.json"));
    }
}
