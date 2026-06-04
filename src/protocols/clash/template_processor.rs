//! Clash template processor

use crate::protocols::{ProtocolProcessor, ProxyServer};
use crate::protocols::shared_resolver::SharedNodeResolver;
use crate::core::error::Result;
use crate::protocols::source::Source;
use crate::utils::template::interpolation_parser::InterpolationRule;
use indexmap::IndexMap;
use serde_json;

/// Clash protocol processor
pub struct ClashProcessor;

impl ProtocolProcessor for ClashProcessor {
    fn process_rule(
        &self,
        rule: &InterpolationRule,
        sources: &IndexMap<String, Source>,
    ) -> Result<String> {
        SharedNodeResolver::process_rule(rule, sources)
    }

    fn get_nodes_for_rule(
        &self,
        rule: &InterpolationRule,
        sources: &IndexMap<String, Source>,
    ) -> Result<Vec<ProxyServer>> {
        SharedNodeResolver::get_nodes_for_rule(rule, sources)
    }

    fn set_default_values(&self, template: &str, nodes: &[ProxyServer]) -> Result<String> {
        // Clash uses similar default value logic as Sing-box
        // Works for both "outbounds" (sing-box style) and "proxy-groups" (clash style)
        let processor = crate::protocols::singbox::template_processor::SingboxProcessor;
        processor.set_default_values(template, nodes)
    }

    fn append_nodes(&self, template: &str, nodes: &[ProxyServer]) -> Result<String> {
        // Parse template as JSON to properly manipulate it
        let mut config: serde_json::Value = serde_json::from_str(template).map_err(|e| {
            crate::core::error::ConvertError::ConfigValidationError(format!(
                "Failed to parse template as JSON: {}",
                e
            ))
        })?;

        // Append nodes to "proxies" array
        if let Some(proxies) = config.get_mut("proxies").and_then(|v| v.as_array_mut()) {
            for node in nodes {
                let node_config = self.create_node_config(node);
                if let Ok(node_value) = serde_json::from_str::<serde_json::Value>(&node_config) {
                    proxies.push(node_value);
                }
            }
        }

        // Serialize back to JSON string
        serde_json::to_string_pretty(&config).map_err(|e| {
            crate::core::error::ConvertError::ConfigValidationError(format!(
                "Failed to serialize config: {}",
                e
            ))
        })
    }

    fn create_node_config(&self, node: &ProxyServer) -> String {
        let mut config = serde_json::Map::new();

        let is_shadowsocks = node.protocol == "shadowsocks" || node.protocol == "ss";
        let is_vmess = node.protocol == "vmess";
        let is_trojan = node.protocol == "trojan";
        let is_anytls = node.protocol == "anytls";

        // For Clash, shadowsocks type should be "ss"
        let protocol_type = if node.protocol == "shadowsocks" {
            "ss".to_string()
        } else {
            node.protocol.clone()
        };

        config.insert(
            "name".to_string(),
            serde_json::Value::String(node.name.clone()),
        );
        config.insert("type".to_string(), serde_json::Value::String(protocol_type));
        config.insert(
            "server".to_string(),
            serde_json::Value::String(node.server.clone()),
        );
        config.insert(
            "port".to_string(),
            serde_json::Value::Number(serde_json::Number::from(node.port)),
        );

        if is_vmess {
            self.convert_vmess_params_to_clash(&mut config, node);
        } else if is_trojan {
            self.convert_trojan_params_to_clash(&mut config, node);
        } else if is_anytls {
            self.convert_anytls_params_to_clash(&mut config, node);
        } else {
            // Generic handling for other protocols
            if let Some(method) = &node.method {
                config.insert(
                    "cipher".to_string(),
                    serde_json::Value::String(method.clone()),
                );
            }

            if let Some(password) = &node.password {
                config.insert(
                    "password".to_string(),
                    serde_json::Value::String(password.clone()),
                );
            }

            // For shadowsocks nodes, always add udp: true
            if is_shadowsocks {
                config.insert("udp".to_string(), serde_json::Value::Bool(true));
            }

            // Add other parameters
            let skip_keys = [
                "udp",
                "name",
                "type",
                "server",
                "port",
                "server_port",
                "tag",
                "method",
            ];
            for (key, value) in node.extras() {
                if !(is_shadowsocks && key == "udp") && !skip_keys.contains(&key.as_str()) {
                    config.insert(key.clone(), value.clone());
                }
            }
        }

        serde_json::to_string_pretty(&serde_json::Value::Object(config))
            .unwrap_or_else(|e| {
                tracing::error!("Failed to serialize clash node config: {}", e);
                "{}".to_string()
            })
    }
}

impl ClashProcessor {
    /// Convert Sing-box VMess parameters to Clash format
    fn convert_vmess_params_to_clash(
        &self,
        config: &mut serde_json::Map<String, serde_json::Value>,
        node: &ProxyServer,
    ) {
        let params = &node.extras();

        // UUID
        if let Some(uuid) = params.get("uuid") {
            config.insert("uuid".to_string(), uuid.clone());
        }

        // alter_id → alterId
        if let Some(alter_id) = params.get("alter_id").or(params.get("alterId")) {
            config.insert("alterId".to_string(), alter_id.clone());
        }

        // security → cipher
        // If sing-box has no security field, it defaults to "auto", so we need to set cipher: auto in Clash
        if let Some(security) = params.get("security") {
            config.insert("cipher".to_string(), security.clone());
        } else {
            // Default to "auto" if no security is specified (sing-box default)
            config.insert(
                "cipher".to_string(),
                serde_json::Value::String("auto".to_string()),
            );
        }

        // UDP support - Clash needs explicit setting
        config.insert("udp".to_string(), serde_json::Value::Bool(true));

        // TLS handling — VMess uses "servername" (not "sni") and needs tls: true boolean
        if let Some(tls) = params.get("tls") {
            if let Some(tls_obj) = tls.as_object() {
                if tls_obj.get("enabled").and_then(|v| v.as_bool()).unwrap_or(false) {
                    config.insert("tls".to_string(), serde_json::Value::Bool(true));
                    // VMess Clash uses "servername" instead of "sni"
                    if let Some(server_name) = tls_obj.get("server_name") {
                        config.insert("servername".to_string(), server_name.clone());
                    }
                    if let Some(insecure) = tls_obj.get("insecure") {
                        config.insert("skip-cert-verify".to_string(), insecure.clone());
                    }
                }
            } else if tls.as_bool().unwrap_or(false) {
                config.insert("tls".to_string(), serde_json::Value::Bool(true));
            }
        }

        // Transport handling — delegate to shared converter
        if let Some(transport) = params.get("transport") {
            crate::protocols::transport_converter::singbox_transport_to_clash(config, transport);
        }
    }

    /// Convert AnyTLS parameters to Clash (mihomo) format.
    /// Maps sing-box-style nested `tls` and snake_case idle-session fields back
    /// to mihomo's flat kebab-case fields.
    fn convert_anytls_params_to_clash(
        &self,
        config: &mut serde_json::Map<String, serde_json::Value>,
        node: &ProxyServer,
    ) {
        let params = &node.extras();

        if let Some(password) = &node.password {
            config.insert(
                "password".to_string(),
                serde_json::Value::String(password.clone()),
            );
        }

        // udp defaults to true; matches what we do for trojan/ss.
        config.insert("udp".to_string(), serde_json::Value::Bool(true));

        // TLS handling — reuse the trojan->clash converter (anytls is always TLS).
        if let Some(tls) = params.get("tls") {
            crate::protocols::transport_converter::singbox_tls_to_clash(config, tls);
        } else {
            // Source had flat fields — propagate them through if present.
            for (snake, kebab) in [
                ("sni", "sni"),
                ("server_name", "sni"),
                ("skip-cert-verify", "skip-cert-verify"),
                ("alpn", "alpn"),
            ] {
                if let Some(v) = params.get(snake) {
                    config.entry(kebab.to_string()).or_insert_with(|| v.clone());
                }
            }
        }

        // Idle session knobs: prefer snake_case (sing-box source), fall back to
        // kebab-case (clash source). Strip "Ns" suffix back to integer where
        // possible so the output looks idiomatic in mihomo YAML.
        let normalize_to_clash = |v: &serde_json::Value| -> serde_json::Value {
            if let Some(s) = v.as_str() {
                if let Some(secs) = s.strip_suffix('s').and_then(|n| n.parse::<u64>().ok()) {
                    return serde_json::Value::Number(serde_json::Number::from(secs));
                }
                serde_json::Value::String(s.to_string())
            } else {
                v.clone()
            }
        };
        for (snake, kebab) in [
            ("idle_session_check_interval", "idle-session-check-interval"),
            ("idle_session_timeout", "idle-session-timeout"),
        ] {
            if let Some(v) = params.get(snake).or_else(|| params.get(kebab)) {
                config.insert(kebab.to_string(), normalize_to_clash(v));
            }
        }
        if let Some(v) = params
            .get("min_idle_session")
            .or_else(|| params.get("min-idle-session"))
        {
            if v.is_number() {
                config.insert("min-idle-session".to_string(), v.clone());
            }
        }

        // client-fingerprint passes through as-is if present.
        if let Some(v) = params.get("client-fingerprint").or_else(|| params.get("client_fingerprint")) {
            config.insert("client-fingerprint".to_string(), v.clone());
        }
    }

    /// Convert Sing-box Trojan parameters to Clash format
    fn convert_trojan_params_to_clash(
        &self,
        config: &mut serde_json::Map<String, serde_json::Value>,
        node: &ProxyServer,
    ) {
        let params = &node.extras();

        // Password
        if let Some(password) = &node.password {
            config.insert(
                "password".to_string(),
                serde_json::Value::String(password.clone()),
            );
        }

        // UDP support
        config.insert("udp".to_string(), serde_json::Value::Bool(true));

        // TLS handling — delegate to shared converter
        if let Some(tls) = params.get("tls") {
            crate::protocols::transport_converter::singbox_tls_to_clash(config, tls);
        }

        // Transport handling — delegate to shared converter
        if let Some(transport) = params.get("transport") {
            crate::protocols::transport_converter::singbox_transport_to_clash(config, transport);
        }
    }

}
