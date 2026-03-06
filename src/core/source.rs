//! Source types - domain model for input sources.
//!
//! Used by commands (to build from CLI) and by utils/protocols (to load and parse).
//! Kept in core to avoid utils depending on commands.

/// Source metadata: path/url + query params (type, name, flag).
#[derive(Debug, Clone)]
pub struct SourceMeta {
    /// Optional display name for multi-source distinction
    pub name: Option<String>,
    /// Protocol type of this source (clash, sing-box, v2ray)
    pub source_type: SourceProtocol,
    /// Full source string: <path|url>?type=...&name=...&flag=...
    pub source: String,
    /// Explicit format override; if None, derived from source_type
    pub format: Option<String>,
    /// If set, use this flag when requesting URL (empty string = &flag=); else use protocol default
    pub flag: Option<String>,
}

/// Supported source (subscription) protocol types.
#[derive(Debug, Clone)]
pub enum SourceProtocol {
    Clash,
    SingBox,
    V2Ray,
}

impl SourceProtocol {
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "clash" => Some(SourceProtocol::Clash),
            "sing-box" | "singbox" => Some(SourceProtocol::SingBox),
            "v2ray" => Some(SourceProtocol::V2Ray),
            _ => None,
        }
    }

    /// Format name for registry/parsing (e.g. "clash", "singbox", "v2ray").
    pub fn as_format_str(&self) -> &'static str {
        match self {
            SourceProtocol::Clash => "clash",
            SourceProtocol::SingBox => "singbox",
            SourceProtocol::V2Ray => "v2ray",
        }
    }
}
