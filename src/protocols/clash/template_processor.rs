//! Clash template processor

use crate::protocols::{ProtocolProcessor, ProxyServer};
use crate::utils::error::Result;
use crate::utils::source::parser::Source;
use crate::utils::template::interpolation_parser::{InterpolationParser, InterpolationRule};
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
        // Clash uses the same rule processing logic as Sing-box
        let processor = crate::protocols::singbox::template_processor::SingboxProcessor;
        processor.process_rule(rule, sources)
    }

    fn get_nodes_for_rule(
        &self,
        rule: &InterpolationRule,
        sources: &IndexMap<String, Source>,
    ) -> Result<Vec<ProxyServer>> {
        // Clash uses the same node extraction logic as Sing-box
        let processor = crate::protocols::singbox::template_processor::SingboxProcessor;
        processor.get_nodes_for_rule(rule, sources)
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
            crate::utils::error::ConvertError::ConfigValidationError(format!(
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
            crate::utils::error::ConvertError::ConfigValidationError(format!(
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
            let skip_keys = ["udp", "name", "type", "server", "port", "server_port", "tag", "method"];
            for (key, value) in &node.parameters {
                if !(is_shadowsocks && key == "udp") && !skip_keys.contains(&key.as_str()) {
                    config.insert(key.clone(), value.clone());
                }
            }
        }

        serde_json::to_string_pretty(&serde_json::Value::Object(config)).unwrap()
    }
}

impl ClashProcessor {
    /// Convert Sing-box VMess parameters to Clash format
    fn convert_vmess_params_to_clash(
        &self,
        config: &mut serde_json::Map<String, serde_json::Value>,
        node: &ProxyServer,
    ) {
        let params = &node.parameters;

        // UUID
        if let Some(uuid) = params.get("uuid") {
            config.insert("uuid".to_string(), uuid.clone());
        }

        // alter_id → alterId
        if let Some(alter_id) = params.get("alter_id").or(params.get("alterId")) {
            config.insert("alterId".to_string(), alter_id.clone());
        }

        // security → cipher
        if let Some(security) = params.get("security") {
            config.insert("cipher".to_string(), security.clone());
        } else if let Some(method) = &node.method {
            config.insert("cipher".to_string(), serde_json::Value::String(method.clone()));
        }

        // UDP support - Clash needs explicit setting
        config.insert("udp".to_string(), serde_json::Value::Bool(true));

        // TLS handling
        if let Some(tls) = params.get("tls") {
            if let Some(tls_obj) = tls.as_object() {
                if tls_obj.get("enabled").and_then(|v| v.as_bool()).unwrap_or(false) {
                    config.insert("tls".to_string(), serde_json::Value::Bool(true));

                    // server_name → servername
                    if let Some(server_name) = tls_obj.get("server_name") {
                        config.insert("servername".to_string(), server_name.clone());
                    }

                    // insecure → skip-cert-verify
                    if let Some(insecure) = tls_obj.get("insecure") {
                        config.insert("skip-cert-verify".to_string(), insecure.clone());
                    }
                }
            } else if tls.as_bool().unwrap_or(false) {
                config.insert("tls".to_string(), serde_json::Value::Bool(true));
            }
        }

        // Transport handling
        if let Some(transport) = params.get("transport") {
            if let Some(transport_obj) = transport.as_object() {
                if let Some(transport_type) = transport_obj.get("type").and_then(|v| v.as_str()) {
                    config.insert(
                        "network".to_string(),
                        serde_json::Value::String(transport_type.to_string()),
                    );

                    match transport_type {
                        "ws" => {
                            let mut ws_opts = serde_json::Map::new();
                            if let Some(path) = transport_obj.get("path") {
                                ws_opts.insert("path".to_string(), path.clone());
                            }
                            if let Some(headers) = transport_obj.get("headers") {
                                ws_opts.insert("headers".to_string(), headers.clone());
                            }
                            if let Some(early_data) = transport_obj.get("max_early_data") {
                                ws_opts.insert("max-early-data".to_string(), early_data.clone());
                            }
                            if let Some(header_name) = transport_obj.get("early_data_header_name") {
                                ws_opts.insert("early-data-header-name".to_string(), header_name.clone());
                            }
                            if !ws_opts.is_empty() {
                                config.insert(
                                    "ws-opts".to_string(),
                                    serde_json::Value::Object(ws_opts),
                                );
                            }
                        }
                        "grpc" => {
                            let mut grpc_opts = serde_json::Map::new();
                            if let Some(service_name) = transport_obj.get("service_name") {
                                grpc_opts.insert("grpc-service-name".to_string(), service_name.clone());
                            }
                            if !grpc_opts.is_empty() {
                                config.insert(
                                    "grpc-opts".to_string(),
                                    serde_json::Value::Object(grpc_opts),
                                );
                            }
                        }
                        "h2" => {
                            let mut h2_opts = serde_json::Map::new();
                            if let Some(host) = transport_obj.get("host") {
                                h2_opts.insert("host".to_string(), host.clone());
                            }
                            if let Some(path) = transport_obj.get("path") {
                                h2_opts.insert("path".to_string(), path.clone());
                            }
                            if !h2_opts.is_empty() {
                                config.insert(
                                    "h2-opts".to_string(),
                                    serde_json::Value::Object(h2_opts),
                                );
                            }
                        }
                        "http" => {
                            let mut http_opts = serde_json::Map::new();
                            if let Some(method) = transport_obj.get("method") {
                                http_opts.insert("method".to_string(), method.clone());
                            }
                            if let Some(path) = transport_obj.get("path") {
                                http_opts.insert("path".to_string(), path.clone());
                            }
                            if let Some(headers) = transport_obj.get("headers") {
                                http_opts.insert("headers".to_string(), headers.clone());
                            }
                            if !http_opts.is_empty() {
                                config.insert(
                                    "http-opts".to_string(),
                                    serde_json::Value::Object(http_opts),
                                );
                            }
                        }
                        _ => {}
                    }
                }
            }
        }
    }

    /// Convert Sing-box Trojan parameters to Clash format
    fn convert_trojan_params_to_clash(
        &self,
        config: &mut serde_json::Map<String, serde_json::Value>,
        node: &ProxyServer,
    ) {
        let params = &node.parameters;

        // Password
        if let Some(password) = &node.password {
            config.insert(
                "password".to_string(),
                serde_json::Value::String(password.clone()),
            );
        }

        // UDP support
        config.insert("udp".to_string(), serde_json::Value::Bool(true));

        // TLS handling - Trojan typically always uses TLS
        if let Some(tls) = params.get("tls") {
            if let Some(tls_obj) = tls.as_object() {
                if let Some(server_name) = tls_obj.get("server_name") {
                    config.insert("sni".to_string(), server_name.clone());
                }
                if let Some(insecure) = tls_obj.get("insecure") {
                    config.insert("skip-cert-verify".to_string(), insecure.clone());
                }
                if let Some(alpn) = tls_obj.get("alpn") {
                    config.insert("alpn".to_string(), alpn.clone());
                }
            }
        }

        // Transport handling
        if let Some(transport) = params.get("transport") {
            if let Some(transport_obj) = transport.as_object() {
                if let Some(transport_type) = transport_obj.get("type").and_then(|v| v.as_str()) {
                    config.insert(
                        "network".to_string(),
                        serde_json::Value::String(transport_type.to_string()),
                    );

                    match transport_type {
                        "ws" => {
                            let mut ws_opts = serde_json::Map::new();
                            if let Some(path) = transport_obj.get("path") {
                                ws_opts.insert("path".to_string(), path.clone());
                            }
                            if let Some(headers) = transport_obj.get("headers") {
                                ws_opts.insert("headers".to_string(), headers.clone());
                            }
                            if !ws_opts.is_empty() {
                                config.insert(
                                    "ws-opts".to_string(),
                                    serde_json::Value::Object(ws_opts),
                                );
                            }
                        }
                        "grpc" => {
                            let mut grpc_opts = serde_json::Map::new();
                            if let Some(service_name) = transport_obj.get("service_name") {
                                grpc_opts.insert("grpc-service-name".to_string(), service_name.clone());
                            }
                            if !grpc_opts.is_empty() {
                                config.insert(
                                    "grpc-opts".to_string(),
                                    serde_json::Value::Object(grpc_opts),
                                );
                            }
                        }
                        _ => {}
                    }
                }
            }
        }
    }

    /// Process proxy-groups interpolation
    /// This method processes each proxy-group's proxies field for interpolation expressions
    pub fn process_proxy_groups(
        &self,
        template: &str,
        sources: &IndexMap<String, Source>,
    ) -> Result<String> {
        let mut config: serde_json::Value = serde_json::from_str(template).map_err(|e| {
            crate::utils::error::ConvertError::ConfigValidationError(format!(
                "Failed to parse template as JSON: {}",
                e
            ))
        })?;

        if let Some(proxy_groups) = config.get_mut("proxy-groups").and_then(|v| v.as_array_mut()) {
            for group in proxy_groups.iter_mut() {
                if let Some(group_obj) = group.as_object_mut() {
                    if let Some(proxies) = group_obj.get_mut("proxies") {
                        self.process_proxies_field(proxies, sources)?;
                    }
                }
            }
        }

        serde_json::to_string_pretty(&config).map_err(|e| {
            crate::utils::error::ConvertError::ConfigValidationError(format!(
                "Failed to serialize config: {}",
                e
            ))
        })
    }

    /// Process a proxies field (can be array or string with interpolation)
    fn process_proxies_field(
        &self,
        proxies: &mut serde_json::Value,
        sources: &IndexMap<String, Source>,
    ) -> Result<()> {
        match proxies {
            serde_json::Value::Array(arr) => {
                let mut new_arr = Vec::new();
                for item in arr.iter() {
                    if let Some(s) = item.as_str() {
                        if s.starts_with("{{") && s.ends_with("}}") {
                            // Parse and process interpolation
                            if let Ok(rule) = InterpolationParser::parse(s) {
                                let nodes = self.get_nodes_for_rule(&rule, sources)?;
                                for node in nodes {
                                    new_arr.push(serde_json::Value::String(node.name));
                                }
                            } else {
                                new_arr.push(item.clone());
                            }
                        } else {
                            new_arr.push(item.clone());
                        }
                    } else {
                        new_arr.push(item.clone());
                    }
                }
                *proxies = serde_json::Value::Array(new_arr);
            }
            serde_json::Value::String(s) => {
                if s.starts_with("{{") && s.ends_with("}}") {
                    // Parse and process interpolation
                    if let Ok(rule) = InterpolationParser::parse(s) {
                        let nodes = self.get_nodes_for_rule(&rule, sources)?;
                        let names: Vec<serde_json::Value> = nodes
                            .iter()
                            .map(|n| serde_json::Value::String(n.name.clone()))
                            .collect();
                        *proxies = serde_json::Value::Array(names);
                    }
                }
            }
            _ => {}
        }
        Ok(())
    }
}
