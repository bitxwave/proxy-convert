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
pub mod source;
pub mod subscription;
pub mod v2ray;
pub mod transport_converter;

pub use source::{Config, Source};

use crate::core::error::Result;
use crate::utils::template::interpolation_parser::InterpolationRule;
use indexmap::IndexMap;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Canonical format keys used by detect/loader for non-protocol content.
pub const FORMAT_SUBSCRIPTION: &str = "subscription";
pub const FORMAT_PLAIN: &str = "plain";

/// Typed proxy-protocol parameters.
///
/// Each variant carries the typed fields that processors need, plus an
/// `extras` map for protocol-specific fields that haven't been typed yet
/// (e.g. obscure transport tweaks). Previously these lived in a flat
/// `ProxyServer.parameters` HashMap, which duplicated the typed data and
/// made it unclear which field was canonical — `extras` makes the scope
/// explicit: "raw leftovers for *this* protocol".
#[derive(Debug, Clone, PartialEq)]
pub enum ProxyParams {
    Shadowsocks {
        cipher: String,
        udp: Option<bool>,
        plugin: Option<String>,
        plugin_opts: Option<String>,
        extras: HashMap<String, serde_json::Value>,
    },
    Vmess {
        uuid: String,
        alter_id: Option<u32>,
        security: Option<String>,
        tls: Option<TlsParams>,
        transport: Option<TransportParams>,
        extras: HashMap<String, serde_json::Value>,
    },
    Trojan {
        tls: Option<TlsParams>,
        transport: Option<TransportParams>,
        extras: HashMap<String, serde_json::Value>,
    },
    Vless {
        uuid: String,
        flow: Option<String>,
        tls: Option<TlsParams>,
        transport: Option<TransportParams>,
        extras: HashMap<String, serde_json::Value>,
    },
    Hysteria2 {
        obfs: Option<String>,
        obfs_password: Option<String>,
        up_mbps: Option<u32>,
        down_mbps: Option<u32>,
        tls: Option<TlsParams>,
        extras: HashMap<String, serde_json::Value>,
    },
    Hysteria {
        auth_str: Option<String>,
        obfs: Option<String>,
        up_mbps: Option<u32>,
        down_mbps: Option<u32>,
        tls: Option<TlsParams>,
        extras: HashMap<String, serde_json::Value>,
    },
    Tuic {
        uuid: Option<String>,
        token: Option<String>,
        congestion_control: Option<String>,
        udp_relay_mode: Option<String>,
        zero_rtt_handshake: Option<bool>,
        heartbeat: Option<String>,
        tls: Option<TlsParams>,
        extras: HashMap<String, serde_json::Value>,
    },
    /// WireGuard params. mihomo accepts both "simplified" (top-level peer) and
    /// full (peers list); we always normalize to a `peers` list when emitting.
    WireGuard {
        private_key: String,
        local_addresses: Vec<String>,
        mtu: Option<u32>,
        peers: Vec<WireGuardPeerParams>,
        extras: HashMap<String, serde_json::Value>,
    },
    /// AnyTLS protocol (https://github.com/anytls/anytls-go).
    /// idle_session_* fields preserve raw values (string/int) so we can re-emit
    /// either Clash (kebab-case, often integer seconds) or sing-box
    /// (snake_case, duration strings) without lossy conversion.
    AnyTls {
        tls: Option<TlsParams>,
        idle_session_check_interval: Option<serde_json::Value>,
        idle_session_timeout: Option<serde_json::Value>,
        min_idle_session: Option<u32>,
        extras: HashMap<String, serde_json::Value>,
    },
    /// ShadowsocksR (legacy SS variant; Clash-only).
    ShadowsocksR {
        cipher: String,
        protocol: String,
        obfs: String,
        obfs_param: Option<String>,
        protocol_param: Option<String>,
        udp: Option<bool>,
        extras: HashMap<String, serde_json::Value>,
    },
    /// SOCKS proxy. Shared between Clash (`socks5`) and sing-box (`socks`,
    /// which adds the `version` discriminator).
    Socks {
        version: Option<String>,
        username: Option<String>,
        tls: Option<TlsParams>,
        udp: Option<bool>,
        extras: HashMap<String, serde_json::Value>,
    },
    /// HTTP/HTTPS proxy. Shared between Clash and sing-box.
    Http {
        username: Option<String>,
        tls: Option<TlsParams>,
        extras: HashMap<String, serde_json::Value>,
    },
    /// Snell (mihomo-only). v3+ uses `psk`+`version` and an optional
    /// `obfs-opts` block whose shape is `{mode, host}`.
    Snell {
        psk: String,
        version: Option<u32>,
        obfs_opts: Option<serde_json::Value>,
        extras: HashMap<String, serde_json::Value>,
    },
    /// Fallback for protocols not yet fully typed.
    Generic {
        extras: HashMap<String, serde_json::Value>,
    },
}

impl Default for ProxyParams {
    fn default() -> Self {
        ProxyParams::Generic { extras: HashMap::new() }
    }
}

impl ProxyParams {
    /// Raw leftover fields for this protocol (e.g. unknown options preserved
    /// verbatim for pass-through). Typed fields should be read from the
    /// variant's named fields, not from here.
    pub fn extras(&self) -> &HashMap<String, serde_json::Value> {
        match self {
            ProxyParams::Shadowsocks { extras, .. }
            | ProxyParams::Vmess { extras, .. }
            | ProxyParams::Trojan { extras, .. }
            | ProxyParams::Vless { extras, .. }
            | ProxyParams::Hysteria2 { extras, .. }
            | ProxyParams::Hysteria { extras, .. }
            | ProxyParams::Tuic { extras, .. }
            | ProxyParams::WireGuard { extras, .. }
            | ProxyParams::AnyTls { extras, .. }
            | ProxyParams::ShadowsocksR { extras, .. }
            | ProxyParams::Socks { extras, .. }
            | ProxyParams::Http { extras, .. }
            | ProxyParams::Snell { extras, .. }
            | ProxyParams::Generic { extras } => extras,
        }
    }
}

/// WireGuard peer params (typed, used inside ProxyParams::WireGuard).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WireGuardPeerParams {
    pub server: String,
    pub server_port: u16,
    pub public_key: String,
    pub pre_shared_key: Option<String>,
    pub allowed_ips: Vec<String>,
    /// Reserved bytes (mihomo allows list `[209,98,59]` or string `"U4An"`).
    /// Stored as raw JSON to keep the input shape verbatim.
    pub reserved: Option<serde_json::Value>,
    pub persistent_keepalive: Option<u32>,
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

/// Proxy server information.
///
/// Protocol-specific fields live inside `params` (and, for not-yet-typed
/// fields, `params.extras()`). There is no flat fallback HashMap on the
/// server itself — read through the typed variant.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProxyServer {
    pub name: String,
    pub protocol: String,
    pub server: String,
    pub port: u16,
    pub password: Option<String>,
    pub method: Option<String>,
    #[serde(skip)]
    pub params: ProxyParams,
}

impl ProxyServer {
    /// Convenience — raw pass-through fields for this server's protocol.
    pub fn extras(&self) -> &HashMap<String, serde_json::Value> {
        self.params.extras()
    }
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

/// Protocol converter registry: a single table of `ProtocolFormat`s that
/// yields descriptor info, parsers, and template processors.
///
/// Uses `IndexMap` so iteration order matches registration order — makes
/// logging and format-detection fallbacks deterministic.
pub struct ProtocolRegistry {
    formats: IndexMap<String, Box<dyn protocol_format::ProtocolFormat>>,
}

impl ProtocolRegistry {
    /// Create new empty registry (for tests or custom setup).
    pub fn new() -> Self {
        Self {
            formats: IndexMap::new(),
        }
    }

    /// Register a protocol. One call per protocol covers both format
    /// descriptor and template processor.
    pub fn register(&mut self, format: Box<dyn protocol_format::ProtocolFormat>) {
        let name = format.name().to_lowercase();
        self.formats.insert(name, format);
    }

    /// Look up a `ProtocolFormat` by canonical name or alias.
    pub fn get_format(&self, name: &str) -> Option<&dyn protocol_format::ProtocolFormat> {
        let lower = name.to_lowercase();
        self.formats
            .get(&lower)
            .map(|b| b.as_ref())
            .or_else(|| {
                self.formats
                    .values()
                    .find(|f| f.aliases().iter().any(|a| a.to_lowercase() == lower))
                    .map(|b| b.as_ref())
            })
    }

    /// Get processor by format name. Used by TemplateEngine.
    pub fn get_processor(&self, format: &str) -> Option<&dyn ProtocolProcessor> {
        self.get_format(format).map(|f| f.processor())
    }

    /// Auto-detect input format (delegates to detect module).
    pub fn auto_detect_format(&self, content: &str) -> Result<Option<(String, String)>> {
        detect::detect_format(content)
    }

    /// Initialize protocol registry with the built-in protocols.
    pub fn init() -> Self {
        let mut registry = Self::new();
        registry.register(Box::new(singbox::format::SingboxFormat));
        registry.register(Box::new(clash::format::ClashFormat));
        registry.register(Box::new(v2ray::format::V2RayFormat));
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
