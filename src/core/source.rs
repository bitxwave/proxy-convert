//! Source types - domain model for input sources.
//!
//! Used by commands (to build from CLI) and by utils/protocols (to load and parse).
//! Kept in core to avoid utils depending on commands.

use std::fmt;
use std::path::PathBuf;
use std::str::FromStr;

use crate::core::error::ConvertError;

/// Where this source lives. Computed once at parse time so downstream
/// code never has to re-inspect the raw `source` string.
#[derive(Debug, Clone)]
pub enum SourceLocation {
    /// Remote URL. Our synthetic query keys (`type`/`name`/`flag`) are
    /// stripped; the user's own query params (tokens, etc.) stay intact.
    Url(url::Url),
    /// Local file path (query portion stripped).
    File(PathBuf),
}

impl fmt::Display for SourceLocation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SourceLocation::Url(u) => f.write_str(u.as_str()),
            SourceLocation::File(p) => write!(f, "{}", p.display()),
        }
    }
}

/// Source metadata: typed location + structured query params.
#[derive(Debug, Clone)]
pub struct SourceMeta {
    /// Optional display name for multi-source distinction
    pub name: Option<String>,
    /// Protocol type of this source (clash, sing-box, v2ray)
    pub source_type: Protocol,
    /// Typed URL or file path — downstream reads from here.
    pub location: SourceLocation,
    /// Raw source string as the user typed it (kept verbatim for logs).
    pub source: String,
    /// Explicit format override; if None, derived from source_type
    pub format: Option<String>,
    /// If set, use this flag when requesting URL (empty string = &flag=); else use protocol default
    pub flag: Option<String>,
}

/// Supported protocol types (unified: source + output).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Protocol {
    Clash,
    SingBox,
    V2Ray,
}

impl Protocol {
    /// Canonical format key used across the registry and detection.
    pub const fn as_format_str(self) -> &'static str {
        match self {
            Protocol::Clash => "clash",
            Protocol::SingBox => "singbox",
            Protocol::V2Ray => "v2ray",
        }
    }

    /// Default output format (`json` or `yaml`).
    pub const fn default_output_format(self) -> &'static str {
        match self {
            Protocol::SingBox => "json",
            Protocol::Clash => "yaml",
            Protocol::V2Ray => "json",
        }
    }

    /// Default filename.
    pub const fn default_filename(self) -> &'static str {
        match self {
            Protocol::SingBox => "config.json",
            Protocol::Clash => "config.yaml",
            Protocol::V2Ray => "config.json",
        }
    }
}

impl fmt::Display for Protocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_format_str())
    }
}

impl FromStr for Protocol {
    type Err = ConvertError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "clash" => Ok(Protocol::Clash),
            "sing-box" | "singbox" => Ok(Protocol::SingBox),
            "v2ray" => Ok(Protocol::V2Ray),
            other => Err(ConvertError::ConfigValidationError(format!(
                "Unsupported protocol: {}, supported: clash, sing-box(singbox), v2ray",
                other
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_roundtrip() {
        assert_eq!("clash".parse::<Protocol>().unwrap(), Protocol::Clash);
        assert_eq!("singbox".parse::<Protocol>().unwrap(), Protocol::SingBox);
        assert_eq!("sing-box".parse::<Protocol>().unwrap(), Protocol::SingBox);
        assert_eq!("SING-BOX".parse::<Protocol>().unwrap(), Protocol::SingBox);
        assert_eq!("v2ray".parse::<Protocol>().unwrap(), Protocol::V2Ray);
        assert!("quic".parse::<Protocol>().is_err());
    }

    #[test]
    fn display_is_canonical_key() {
        assert_eq!(Protocol::Clash.to_string(), "clash");
        assert_eq!(Protocol::SingBox.to_string(), "singbox");
        assert_eq!(Protocol::V2Ray.to_string(), "v2ray");
    }
}
