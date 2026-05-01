//! ProtocolFormat trait -- everything needed to support a proxy protocol format.
//!
//! Implementing this trait for a new protocol and registering it in
//! `ProtocolRegistry::init()` is all that is needed to add a new format.

use crate::core::error::Result;
use crate::protocols::source::Config;

/// Everything needed to support a proxy protocol format.
pub trait ProtocolFormat: Send + Sync {
    /// Canonical format name used as registry key ("clash", "singbox", "v2ray").
    fn name(&self) -> &'static str;

    /// Alternate names for matching (e.g., "sing-box" for "singbox").
    fn aliases(&self) -> &'static [&'static str] {
        &[]
    }

    /// File extension for output ("json", "yaml").
    fn config_ext(&self) -> &'static str;

    /// Default output filename (e.g. "config.json").
    fn default_filename(&self) -> &'static str;

    /// Generate a default template string for this protocol.
    fn default_template(&self) -> String;

    /// Validate a config string for this protocol.
    fn validate(&self, content: &str) -> Result<()>;

    /// Parse a raw config string into the strongly-typed `Config` enum.
    fn parse_config(&self, content: &str) -> Result<Config>;
}
