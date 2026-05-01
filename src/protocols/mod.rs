//! Protocol Module - Handle conversion between different proxy configuration formats.
//!
//! - **detect**: Format detection (clash/singbox/v2ray/subscription/plain).
//! - **subscription**: Parse subscription and plain-text proxy URLs.
//! - **Registry**: Holds ProtocolProcessors and delegates parsing to protocol submodules and subscription.

pub mod clash;
pub mod detect;
pub mod protocol_format;
pub mod shared_resolver;
pub mod singbox;
pub mod subscription;
pub mod v2ray;
pub mod transport_converter;

use crate::core::error::Result;
use crate::utils::source::parser::Source;
use crate::utils::template::interpolation_parser::InterpolationRule;
use indexmap::IndexMap;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Canonical format keys used by detect/loader for non-protocol content.
pub const FORMAT_SUBSCRIPTION: &str = "subscription";
pub const FORMAT_PLAIN: &str = "plain";

/// Typed proxy protocol parameters
#[derive(Debug, Clone, PartialEq)]
pub enum ProxyParams {
    Shadowsocks {
        cipher: String,
        udp: Option<bool>,
        plugin: Option<String>,
        plugin_opts: Option<String>,
    },
    Vmess {
        uuid: String,
        alter_id: Option<u32>,
        security: Option<String>,
        tls: Option<TlsParams>,
        transport: Option<TransportParams>,
    },
    Trojan {
        tls: Option<TlsParams>,
        transport: Option<TransportParams>,
    },
    Vless {
        uuid: String,
        flow: Option<String>,
        tls: Option<TlsParams>,
        transport: Option<TransportParams>,
    },
    Hysteria2 {
        obfs_password: Option<String>,
        tls: Option<TlsParams>,
    },
    /// Fallback for protocols not yet fully typed
    Generic,
}

impl Default for ProxyParams {
    fn default() -> Self {
        ProxyParams::Generic
    }
}

/// TLS configuration (shared across protocols)
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TlsParams {
    pub enabled: bool,
    pub server_name: Option<String>,
    pub insecure: Option<bool>,
    pub alpn: Option<Vec<String>>,
}

/// Transport configuration (shared across protocols)
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TransportParams {
    pub transport_type: String,
    pub path: Option<String>,
    pub host: Option<Vec<String>>,
    pub service_name: Option<String>,
    pub headers: Option<std::collections::HashMap<String, serde_json::Value>>,
    pub max_early_data: Option<usize>,
    pub early_data_header_name: Option<String>,
}

/// Proxy server information
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProxyServer {
    /// Server name
    pub name: String,
    /// Server type
    pub protocol: String,
    /// Server address
    pub server: String,
    /// Server port
    pub port: u16,
    /// Password (if needed)
    pub password: Option<String>,
    /// Encryption method (if needed)
    pub method: Option<String>,
    /// Additional parameters (legacy HashMap, kept for backward compatibility)
    pub parameters: HashMap<String, serde_json::Value>,
    /// Typed parameters (new, preferred for reading protocol-specific data)
    #[serde(skip)]
    pub params: ProxyParams,
}

/// Protocol processor trait - each protocol implements this for template processing.
pub trait ProtocolProcessor: Send + Sync {
    /// Process interpolation rules for this protocol
    fn process_rule(
        &self,
        rule: &InterpolationRule,
        sources: &IndexMap<String, Source>,
    ) -> Result<String>;

    /// Get nodes for a specific rule
    fn get_nodes_for_rule(
        &self,
        rule: &InterpolationRule,
        sources: &IndexMap<String, Source>,
    ) -> Result<Vec<ProxyServer>>;

    /// Process default field values
    fn set_default_values(
        &self,
        template: &str,
        nodes: &[ProxyServer],
    ) -> Result<String>;

    /// Append nodes to the configuration
    fn append_nodes(
        &self,
        template: &str,
        nodes: &[ProxyServer],
    ) -> Result<String>;

    /// Create node configuration for this protocol
    fn create_node_config(&self, node: &ProxyServer) -> String;
}

/// Protocol converter registry: format detection, parsing, and processor lookup.
///
/// Uses `IndexMap` so iteration order matches registration order — makes
/// logging and format-detection fallbacks deterministic.
pub struct ProtocolRegistry {
    processors: IndexMap<String, Box<dyn ProtocolProcessor>>,
    formats: IndexMap<String, Box<dyn protocol_format::ProtocolFormat>>,
}

impl ProtocolRegistry {
    /// Create new empty registry (for tests or custom setup).
    pub fn new() -> Self {
        Self {
            processors: IndexMap::new(),
            formats: IndexMap::new(),
        }
    }

    /// Register a processor for a format name (e.g. "clash", "singbox", "v2ray").
    pub fn register(&mut self, format: &str, processor: Box<dyn ProtocolProcessor>) {
        self.processors.insert(format.to_lowercase(), processor);
    }

    /// Register a `ProtocolFormat` descriptor.
    pub fn register_format(&mut self, format: Box<dyn protocol_format::ProtocolFormat>) {
        let name = format.name().to_string();
        self.formats.insert(name.to_lowercase(), format);
    }

    /// Look up a `ProtocolFormat` by canonical name or alias.
    pub fn get_format(&self, name: &str) -> Option<&dyn protocol_format::ProtocolFormat> {
        let lower = name.to_lowercase();
        self.formats
            .get(&lower)
            .map(|b| b.as_ref())
            .or_else(|| {
                // Fall back to alias search
                self.formats
                    .values()
                    .find(|f| f.aliases().iter().any(|a| a.to_lowercase() == lower))
                    .map(|b| b.as_ref())
            })
    }

    /// Get processor by format name. Used by TemplateEngine.
    pub fn get_processor(&self, format: &str) -> Option<&dyn ProtocolProcessor> {
        self.processors.get(&format.to_lowercase()).map(|b| b.as_ref())
    }

    /// Auto-detect input format (delegates to detect module).
    pub fn auto_detect_format(&self, content: &str) -> Result<Option<(String, String)>> {
        detect::detect_format(content)
    }

    /// Initialize protocol registry with built-in processors and format descriptors.
    pub fn init() -> Self {
        use crate::core::source::Protocol;
        let mut registry = Self::new();
        // Processors (used by TemplateEngine)
        registry.register(Protocol::Clash.as_format_str(), Box::new(clash::template_processor::ClashProcessor));
        registry.register(Protocol::SingBox.as_format_str(), Box::new(singbox::template_processor::SingboxProcessor));
        registry.register(Protocol::V2Ray.as_format_str(), Box::new(v2ray::template_processor::V2RayProcessor));
        // Format descriptors (validate, parse, default template, metadata)
        registry.register_format(Box::new(singbox::format::SingboxFormat));
        registry.register_format(Box::new(clash::format::ClashFormat));
        registry.register_format(Box::new(v2ray::format::V2RayFormat));
        tracing::info!("Protocol registry initialized successfully");
        registry
    }

    /// Parse subscription format to ProxyServer list. Public API for SourceLoader.
    pub fn parse_subscription_to_servers(&self, content: &str) -> Result<Vec<ProxyServer>> {
        subscription::parse_subscription(content)
    }

    /// Parse plain text format to ProxyServer list. Public API for SourceLoader.
    pub fn parse_plain_text_to_servers(&self, content: &str) -> Result<Vec<ProxyServer>> {
        subscription::parse_plain_text(content)
    }
}

impl Default for ProtocolRegistry {
    fn default() -> Self {
        Self::new()
    }
}
