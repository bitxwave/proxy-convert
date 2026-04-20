//! V2Ray template processor

use crate::protocols::{ProtocolProcessor, ProxyServer};
use crate::protocols::shared_resolver::SharedNodeResolver;
use crate::core::error::Result;
use crate::utils::source::parser::Source;
use crate::utils::template::interpolation_parser::InterpolationRule;
use indexmap::IndexMap;

/// V2Ray protocol processor
pub struct V2RayProcessor;

impl ProtocolProcessor for V2RayProcessor {
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

    fn set_default_values(
        &self,
        template: &str,
        nodes: &[ProxyServer],
    ) -> Result<String> {
        // V2Ray uses the same default value logic as Sing-box
        let processor = crate::protocols::singbox::template_processor::SingboxProcessor;
        processor.set_default_values(template, nodes)
    }

    fn append_nodes(
        &self,
        template: &str,
        nodes: &[ProxyServer],
    ) -> Result<String> {
        let mut config: serde_json::Value = serde_json::from_str(template).map_err(|e| {
            crate::core::error::ConvertError::ConfigValidationError(format!(
                "Failed to parse V2Ray template as JSON: {}", e
            ))
        })?;

        if let Some(outbounds) = config.get_mut("outbounds").and_then(|v| v.as_array_mut()) {
            for node in nodes {
                let node_config = self.create_node_config(node);
                if let Ok(node_value) = serde_json::from_str::<serde_json::Value>(&node_config) {
                    outbounds.push(node_value);
                }
            }
        }

        serde_json::to_string_pretty(&config).map_err(|e| {
            crate::core::error::ConvertError::ConfigValidationError(format!(
                "Failed to serialize V2Ray config: {}", e
            ))
        })
    }

    fn create_node_config(&self, node: &ProxyServer) -> String {
        let mut config = serde_json::Map::new();

        config.insert(
            "tag".to_string(),
            serde_json::Value::String(node.name.clone()),
        );

        let is_vmess = node.protocol == "vmess";
        let is_trojan = node.protocol == "trojan";
        let is_shadowsocks = node.protocol == "ss" || node.protocol == "shadowsocks";

        if is_vmess {
            config.insert(
                "protocol".to_string(),
                serde_json::Value::String("vmess".to_string()),
            );

            let uuid = node.parameters.get("uuid")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let alter_id = node.parameters.get("alterId")
                .or(node.parameters.get("alter_id"))
                .cloned()
                .unwrap_or(serde_json::Value::Number(0.into()));
            let security = node.method.clone()
                .or_else(|| node.parameters.get("security").and_then(|v| v.as_str()).map(|s| s.to_string()))
                .unwrap_or_else(|| "auto".to_string());

            let mut user = serde_json::Map::new();
            user.insert("id".to_string(), serde_json::Value::String(uuid));
            user.insert("alterId".to_string(), alter_id);
            user.insert("security".to_string(), serde_json::Value::String(security));

            let mut vnext_entry = serde_json::Map::new();
            vnext_entry.insert("address".to_string(), serde_json::Value::String(node.server.clone()));
            vnext_entry.insert("port".to_string(), serde_json::Value::Number(serde_json::Number::from(node.port)));
            vnext_entry.insert("users".to_string(), serde_json::Value::Array(vec![serde_json::Value::Object(user)]));

            let mut settings = serde_json::Map::new();
            settings.insert("vnext".to_string(), serde_json::Value::Array(vec![serde_json::Value::Object(vnext_entry)]));
            config.insert("settings".to_string(), serde_json::Value::Object(settings));
        } else if is_trojan {
            config.insert(
                "protocol".to_string(),
                serde_json::Value::String("trojan".to_string()),
            );

            let password = node.password.clone().unwrap_or_default();

            let mut server_entry = serde_json::Map::new();
            server_entry.insert("address".to_string(), serde_json::Value::String(node.server.clone()));
            server_entry.insert("port".to_string(), serde_json::Value::Number(serde_json::Number::from(node.port)));
            server_entry.insert("password".to_string(), serde_json::Value::String(password));

            let mut settings = serde_json::Map::new();
            settings.insert("servers".to_string(), serde_json::Value::Array(vec![serde_json::Value::Object(server_entry)]));
            config.insert("settings".to_string(), serde_json::Value::Object(settings));
        } else if is_shadowsocks {
            config.insert(
                "protocol".to_string(),
                serde_json::Value::String("shadowsocks".to_string()),
            );

            let password = node.password.clone().unwrap_or_default();
            let method = node.method.clone().unwrap_or_default();

            let mut server_entry = serde_json::Map::new();
            server_entry.insert("address".to_string(), serde_json::Value::String(node.server.clone()));
            server_entry.insert("port".to_string(), serde_json::Value::Number(serde_json::Number::from(node.port)));
            server_entry.insert("password".to_string(), serde_json::Value::String(password));
            server_entry.insert("method".to_string(), serde_json::Value::String(method));

            let mut settings = serde_json::Map::new();
            settings.insert("servers".to_string(), serde_json::Value::Array(vec![serde_json::Value::Object(server_entry)]));
            config.insert("settings".to_string(), serde_json::Value::Object(settings));
        } else {
            // Fallback: flat dump for unknown protocols
            config.insert(
                "protocol".to_string(),
                serde_json::Value::String(node.protocol.clone()),
            );
            for (key, value) in &node.parameters {
                config.insert(key.clone(), value.clone());
            }
        }

        // Add streamSettings if tls or transport parameters are present
        let mut stream_settings = serde_json::Map::new();

        if let Some(tls) = node.parameters.get("tls") {
            if let Some(tls_obj) = tls.as_object() {
                let enabled = tls_obj.get("enabled")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);
                if enabled {
                    stream_settings.insert(
                        "security".to_string(),
                        serde_json::Value::String("tls".to_string()),
                    );
                    let mut tls_settings = serde_json::Map::new();
                    if let Some(sni) = tls_obj.get("server_name").or(tls_obj.get("serverName")) {
                        tls_settings.insert("serverName".to_string(), sni.clone());
                    }
                    if let Some(insecure) = tls_obj.get("insecure").or(tls_obj.get("allowInsecure")) {
                        tls_settings.insert("allowInsecure".to_string(), insecure.clone());
                    }
                    if !tls_settings.is_empty() {
                        stream_settings.insert(
                            "tlsSettings".to_string(),
                            serde_json::Value::Object(tls_settings),
                        );
                    }
                }
            }
        }

        if let Some(transport) = node.parameters.get("transport") {
            if let Some(transport_obj) = transport.as_object() {
                if let Some(transport_type) = transport_obj.get("type").and_then(|v| v.as_str()) {
                    stream_settings.insert(
                        "network".to_string(),
                        serde_json::Value::String(transport_type.to_string()),
                    );
                    match transport_type {
                        "ws" => {
                            let mut ws_settings = serde_json::Map::new();
                            if let Some(path) = transport_obj.get("path") {
                                ws_settings.insert("path".to_string(), path.clone());
                            }
                            if let Some(headers) = transport_obj.get("headers") {
                                ws_settings.insert("headers".to_string(), headers.clone());
                            }
                            if !ws_settings.is_empty() {
                                stream_settings.insert(
                                    "wsSettings".to_string(),
                                    serde_json::Value::Object(ws_settings),
                                );
                            }
                        }
                        "grpc" => {
                            let mut grpc_settings = serde_json::Map::new();
                            if let Some(service_name) = transport_obj.get("service_name") {
                                grpc_settings.insert("serviceName".to_string(), service_name.clone());
                            }
                            if !grpc_settings.is_empty() {
                                stream_settings.insert(
                                    "grpcSettings".to_string(),
                                    serde_json::Value::Object(grpc_settings),
                                );
                            }
                        }
                        "h2" | "http" => {
                            let mut http_settings = serde_json::Map::new();
                            if let Some(path) = transport_obj.get("path") {
                                http_settings.insert("path".to_string(), path.clone());
                            }
                            if let Some(host) = transport_obj.get("host") {
                                http_settings.insert("host".to_string(), host.clone());
                            }
                            if !http_settings.is_empty() {
                                stream_settings.insert(
                                    "httpSettings".to_string(),
                                    serde_json::Value::Object(http_settings),
                                );
                            }
                        }
                        _ => {}
                    }
                }
            }
        }

        if !stream_settings.is_empty() {
            config.insert(
                "streamSettings".to_string(),
                serde_json::Value::Object(stream_settings),
            );
        }

        serde_json::to_string_pretty(&serde_json::Value::Object(config))
            .unwrap_or_else(|e| {
                tracing::error!("Failed to serialize v2ray node config: {}", e);
                "{}".to_string()
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocols::{ProxyParams, ProxyServer};
    use std::collections::HashMap;

    #[test]
    fn test_create_vmess_node_config() {
        let processor = V2RayProcessor;
        let mut params = HashMap::new();
        params.insert("uuid".to_string(), serde_json::Value::String("test-uuid".to_string()));
        params.insert("alterId".to_string(), serde_json::Value::Number(0.into()));
        let server = ProxyServer {
            name: "test".to_string(),
            protocol: "vmess".to_string(),
            server: "1.2.3.4".to_string(),
            port: 443,
            password: None,
            method: None,
            parameters: params,
            params: ProxyParams::Generic,
        };
        let config = processor.create_node_config(&server);
        let parsed: serde_json::Value = serde_json::from_str(&config).unwrap();
        assert_eq!(parsed["protocol"], "vmess");
        assert_eq!(parsed["settings"]["vnext"][0]["address"], "1.2.3.4");
        assert_eq!(parsed["settings"]["vnext"][0]["port"], 443);
        assert_eq!(parsed["settings"]["vnext"][0]["users"][0]["id"], "test-uuid");
    }

    #[test]
    fn test_create_trojan_node_config() {
        let processor = V2RayProcessor;
        let server = ProxyServer {
            name: "trojan-test".to_string(),
            protocol: "trojan".to_string(),
            server: "5.6.7.8".to_string(),
            port: 8443,
            password: Some("my-pass".to_string()),
            method: None,
            parameters: HashMap::new(),
            params: ProxyParams::Generic,
        };
        let config = processor.create_node_config(&server);
        let parsed: serde_json::Value = serde_json::from_str(&config).unwrap();
        assert_eq!(parsed["protocol"], "trojan");
        assert_eq!(parsed["settings"]["servers"][0]["address"], "5.6.7.8");
        assert_eq!(parsed["settings"]["servers"][0]["password"], "my-pass");
    }
}

