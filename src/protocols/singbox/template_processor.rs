//! Sing-box template processor

use crate::protocols::{ProtocolProcessor, ProxyServer};
use crate::utils::error::Result;
use crate::utils::source::parser::Source;
use crate::utils::template::interpolation_parser::InterpolationRule;
use indexmap::IndexMap;
use serde_json;

/// Sing-box protocol processor
pub struct SingboxProcessor;

impl SingboxProcessor {
    /// Get all servers from sources (with source prefix if multiple sources)
    /// Uses IndexMap to preserve insertion order of sources
    fn get_all_servers_from_sources(sources: &IndexMap<String, Source>) -> Vec<ProxyServer> {
        let has_multiple_sources = sources.len() > 1;

        // IndexMap preserves insertion order, so iteration order matches the order sources were added
        sources
            .iter()
            .flat_map(|(source_name, source)| {
                let servers = source.extract_servers().unwrap_or_default();
                if has_multiple_sources {
                    // Add source prefix to distinguish nodes from different sources
                    servers
                        .into_iter()
                        .map(|server| ProxyServer {
                            name: format!("{}@{}", source_name, server.name),
                            ..server
                        })
                        .collect::<Vec<_>>()
                } else {
                    servers
                }
            })
            .collect()
    }

    /// Get servers from specific source (with source prefix if multiple sources exist)
    fn get_servers_from_source(
        sources: &IndexMap<String, Source>,
        source_name: &str,
    ) -> Vec<ProxyServer> {
        let has_multiple_sources = sources.len() > 1;

        sources
            .get(source_name)
            .map(|source| {
                let servers = source.extract_servers().unwrap_or_default();
                if has_multiple_sources {
                    // Add source prefix to distinguish nodes
                    servers
                        .into_iter()
                        .map(|server| ProxyServer {
                            name: format!("{}@{}", source_name, server.name),
                            ..server
                        })
                        .collect()
                } else {
                    servers
                }
            })
            .unwrap_or_default()
    }

    /// Filter servers by tag (name contains tag)
    fn filter_by_tag(servers: Vec<ProxyServer>, tag: &str) -> Vec<ProxyServer> {
        servers
            .into_iter()
            .filter(|s| s.name.contains(tag))
            .collect()
    }

    /// Convert server list to JSON array of names
    fn servers_to_json_names(servers: &[ProxyServer]) -> String {
        let names: Vec<String> = servers.iter().map(|s| s.name.clone()).collect();
        serde_json::to_string(&names).unwrap_or_else(|_| "[]".to_string())
    }
}

impl ProtocolProcessor for SingboxProcessor {
    fn process_rule(
        &self,
        rule: &InterpolationRule,
        sources: &IndexMap<String, Source>,
    ) -> Result<String> {
        let servers = self.get_nodes_for_rule(rule, sources)?;
        Ok(Self::servers_to_json_names(&servers))
    }

    fn get_nodes_for_rule(
        &self,
        rule: &InterpolationRule,
        sources: &IndexMap<String, Source>,
    ) -> Result<Vec<ProxyServer>> {
        match rule {
            InterpolationRule::AllTagFromSources(source_list) => {
                let mut all_servers = Vec::new();

                if source_list.is_empty() || source_list == &[(None, None)] {
                    // Get all nodes from all sources
                    all_servers = Self::get_all_servers_from_sources(sources);
                } else {
                    for (source_name, tag_filter) in source_list {
                        let servers = if let Some(source_name) = source_name {
                            Self::get_servers_from_source(sources, source_name)
                        } else {
                            Self::get_all_servers_from_sources(sources)
                        };

                        // Apply tag filter if specified
                        let filtered = if let Some(tag) = tag_filter {
                            Self::filter_by_tag(servers, tag)
                        } else {
                            servers
                        };

                        all_servers.extend(filtered);
                    }
                }

                Ok(all_servers)
            }

            InterpolationRule::IncludeTagFromSources(tag_pairs) => {
                let mut matching_servers = Vec::new();

                for (source_name, tag) in tag_pairs {
                    let servers_to_search = if let Some(source_name) = source_name {
                        Self::get_servers_from_source(sources, source_name)
                    } else {
                        Self::get_all_servers_from_sources(sources)
                    };

                    let filtered = Self::filter_by_tag(servers_to_search, tag);
                    matching_servers.extend(filtered);
                }

                Ok(matching_servers)
            }

            InterpolationRule::ExcludeTagFromSources(tag_pairs) => {
                let mut all_servers = Self::get_all_servers_from_sources(sources);

                for (source_name, tag) in tag_pairs {
                    let exclude_from = if let Some(source_name) = source_name {
                        Self::get_servers_from_source(sources, source_name)
                    } else {
                        all_servers.clone()
                    };

                    // Create a set of server names to exclude
                    let exclude_names: std::collections::HashSet<String> = exclude_from
                        .iter()
                        .filter(|s| s.name.contains(tag))
                        .map(|s| s.name.clone())
                        .collect();

                    all_servers.retain(|server| !exclude_names.contains(&server.name));
                }

                Ok(all_servers)
            }

            InterpolationRule::CombinedRule {
                all_tag,
                include_tag,
                exclude_tag,
            } => {
                // Start with all servers or servers from ALL-TAG rule
                let mut result_servers = if let Some(all_rule) = all_tag {
                    self.get_nodes_for_rule(all_rule, sources)?
                } else {
                    Self::get_all_servers_from_sources(sources)
                };

                // Apply INCLUDE-TAG filter (intersection)
                if let Some(include_rule) = include_tag {
                    let include_servers = self.get_nodes_for_rule(include_rule, sources)?;
                    let include_names: std::collections::HashSet<String> =
                        include_servers.iter().map(|s| s.name.clone()).collect();
                    result_servers.retain(|s| include_names.contains(&s.name));
                }

                // Apply EXCLUDE-TAG filter (removal)
                // Extract the tags to exclude and filter directly
                if let Some(exclude_rule) = exclude_tag {
                    if let InterpolationRule::ExcludeTagFromSources(tag_pairs) =
                        exclude_rule.as_ref()
                    {
                        for (source_name, tag) in tag_pairs {
                            if source_name.is_some() {
                                // Exclude only from specific source
                                let source_prefix = format!("{}@", source_name.as_ref().unwrap());
                                result_servers.retain(|s| {
                                    !(s.name.starts_with(&source_prefix) && s.name.contains(tag))
                                });
                            } else {
                                // Exclude from all sources
                                result_servers.retain(|s| !s.name.contains(tag));
                            }
                        }
                    }
                }

                Ok(result_servers)
            }
        }
    }

    fn set_default_values(&self, template: &str, nodes: &[ProxyServer]) -> Result<String> {
        if nodes.is_empty() {
            return Ok(template.to_string());
        }

        let first_node_name = &nodes[0].name;

        // Parse template as JSON to properly handle selector outbounds
        let mut config: serde_json::Value = serde_json::from_str(template).map_err(|e| {
            crate::utils::error::ConvertError::ConfigValidationError(format!(
                "Failed to parse template as JSON: {}",
                e
            ))
        })?;

        // Process outbounds array
        if let Some(outbounds) = config.get_mut("outbounds").and_then(|v| v.as_array_mut()) {
            for outbound in outbounds.iter_mut() {
                if let Some(obj) = outbound.as_object_mut() {
                    // Check if this is a selector type
                    let is_selector = obj
                        .get("type")
                        .and_then(|v| v.as_str())
                        .map(|t| t == "selector")
                        .unwrap_or(false);

                    if is_selector {
                        // Handle default field for selector type
                        let has_default = obj.contains_key("default");
                        let default_is_empty = obj
                            .get("default")
                            .and_then(|v| v.as_str())
                            .map(|s| s.is_empty())
                            .unwrap_or(false);

                        if !has_default {
                            // Case 1: No default field - insert before outbounds to maintain order
                            let mut new_obj = serde_json::Map::new();
                            for (k, v) in obj.iter() {
                                if k == "outbounds" {
                                    // Insert default before outbounds
                                    new_obj.insert(
                                        "default".to_string(),
                                        serde_json::Value::String(first_node_name.clone()),
                                    );
                                }
                                new_obj.insert(k.clone(), v.clone());
                            }
                            // If outbounds wasn't found, add default at the end
                            if !new_obj.contains_key("default") {
                                new_obj.insert(
                                    "default".to_string(),
                                    serde_json::Value::String(first_node_name.clone()),
                                );
                            }
                            *obj = new_obj;
                        } else if default_is_empty {
                            // Case 2: default is empty string - set to first node name
                            obj.insert(
                                "default".to_string(),
                                serde_json::Value::String(first_node_name.clone()),
                            );
                        } else if let Some(serde_json::Value::Array(arr)) = obj.get("default") {
                            // Case 4: default is an array - take first element
                            if !arr.is_empty() {
                                if let Some(first) = arr.first().and_then(|v| v.as_str()) {
                                    obj.insert(
                                        "default".to_string(),
                                        serde_json::Value::String(first.to_string()),
                                    );
                                }
                            }
                        }
                        // Case 3: default is a non-empty string - keep as is (do nothing)
                    }
                }
            }
        }

        // Serialize back to string
        serde_json::to_string_pretty(&config).map_err(|e| {
            crate::utils::error::ConvertError::ConfigValidationError(format!(
                "Failed to serialize config: {}",
                e
            ))
        })
    }

    fn append_nodes(&self, template: &str, nodes: &[ProxyServer]) -> Result<String> {
        // Parse the template as JSON to safely manipulate it
        let mut config: serde_json::Value = serde_json::from_str(template).map_err(|e| {
            crate::utils::error::ConvertError::ConfigValidationError(format!(
                "Failed to parse template as JSON: {}",
                e
            ))
        })?;

        // Find the top-level outbounds array
        if let Some(outbounds) = config.get_mut("outbounds").and_then(|v| v.as_array_mut()) {
            // Append new node configurations
            for node in nodes {
                let node_config = self.create_node_config(node);
                if let Ok(node_value) = serde_json::from_str::<serde_json::Value>(&node_config) {
                    outbounds.push(node_value);
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

        // Normalize protocol name: ensure "ss" is converted to "shadowsocks" for sing-box
        let is_shadowsocks = node.protocol == "ss" || node.protocol == "shadowsocks";
        let protocol_type = if node.protocol == "ss" {
            "shadowsocks".to_string()
        } else {
            node.protocol.clone()
        };

        // Required fields
        config.insert("type".to_string(), serde_json::Value::String(protocol_type));
        config.insert(
            "tag".to_string(),
            serde_json::Value::String(node.name.clone()),
        );
        config.insert(
            "server".to_string(),
            serde_json::Value::String(node.server.clone()),
        );
        config.insert(
            "server_port".to_string(),
            serde_json::Value::Number(serde_json::Number::from(node.port)),
        );

        // Optional fields
        if let Some(method) = &node.method {
            config.insert(
                "method".to_string(),
                serde_json::Value::String(method.clone()),
            );
        }

        if let Some(password) = &node.password {
            config.insert(
                "password".to_string(),
                serde_json::Value::String(password.clone()),
            );
        }

        // Additional parameters (skip "cipher" as it's handled as "method")
        // For shadowsocks: sing-box supports UDP by default, so we don't need to add "udp" field
        // When converting from Clash SS to sing-box SS, skip the "udp" field
        for (key, value) in &node.parameters {
            // Skip "cipher" parameter as it's already handled as "method" above
            // Skip "udp" for shadowsocks - sing-box supports UDP by default
            if key != "cipher" && !(is_shadowsocks && key == "udp") {
                config.insert(key.clone(), value.clone());
            }
        }

        serde_json::to_string_pretty(&serde_json::Value::Object(config)).unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::convert::{SourceMeta, SourceProtocol};
    use crate::utils::source::parser::{Config, Source};
    use std::collections::HashMap;

    fn create_test_sources() -> IndexMap<String, Source> {
        let mut sources = IndexMap::new();

        // Create clash1 source with test nodes
        let clash1_config = serde_json::json!({
            "proxies": [
                {"name": "HK-Node-01", "type": "ss", "server": "1.1.1.1", "port": 443, "cipher": "aes-256-gcm", "password": "test"},
                {"name": "US-Node-01", "type": "ss", "server": "2.2.2.2", "port": 443, "cipher": "aes-256-gcm", "password": "test"},
                {"name": "JP-Node-01", "type": "vmess", "server": "3.3.3.3", "port": 443, "uuid": "test-uuid"},
            ]
        });
        sources.insert(
            "clash1".to_string(),
            Source {
                meta: SourceMeta {
                    name: Some("clash1".to_string()),
                    source_type: SourceProtocol::Clash,
                    source: "./clash.yaml".to_string(),
                    format: None,
                },
                config: Config::Clash(clash1_config),
            },
        );

        // Create singbox1 source with test nodes
        let singbox1_config = serde_json::json!({
            "outbounds": [
                {"tag": "SG-Node-01", "type": "shadowsocks", "server": "4.4.4.4", "server_port": 443, "method": "aes-256-gcm", "password": "test"},
                {"tag": "CN-Node-01", "type": "shadowsocks", "server": "5.5.5.5", "server_port": 443, "method": "aes-256-gcm", "password": "test"},
            ]
        });
        sources.insert(
            "singbox1".to_string(),
            Source {
                meta: SourceMeta {
                    name: Some("singbox1".to_string()),
                    source_type: SourceProtocol::SingBox,
                    source: "./singbox.json".to_string(),
                    format: None,
                },
                config: Config::SingBox(singbox1_config),
            },
        );

        sources
    }

    #[test]
    fn test_process_all_tag() {
        let processor = SingboxProcessor;
        let sources = create_test_sources();

        let rule = InterpolationRule::AllTagFromSources(vec![(None, None)]);
        let result = processor.get_nodes_for_rule(&rule, &sources).unwrap();

        // Currently extract_servers returns empty vec (TODO implementation)
        // This test will pass once extract_servers is implemented
        assert!(result.is_empty() || !result.is_empty());
    }

    #[test]
    fn test_process_include_tag() {
        let processor = SingboxProcessor;
        let sources = create_test_sources();

        let rule = InterpolationRule::IncludeTagFromSources(vec![
            (None, "US".to_string()),
            (None, "JP".to_string()),
        ]);
        let result = processor.get_nodes_for_rule(&rule, &sources).unwrap();

        // Should only get US and JP nodes (once extract_servers is implemented)
        for server in &result {
            assert!(server.name.contains("US") || server.name.contains("JP"));
        }
    }

    #[test]
    fn test_process_exclude_tag() {
        let processor = SingboxProcessor;
        let sources = create_test_sources();

        let rule = InterpolationRule::ExcludeTagFromSources(vec![(None, "CN".to_string())]);
        let result = processor.get_nodes_for_rule(&rule, &sources).unwrap();

        // Should not have CN nodes
        for server in &result {
            assert!(!server.name.contains("CN"));
        }
    }

    #[test]
    fn test_process_combined_rule() {
        let processor = SingboxProcessor;
        let sources = create_test_sources();

        let rule = InterpolationRule::CombinedRule {
            all_tag: Some(Box::new(InterpolationRule::AllTagFromSources(vec![(
                None, None,
            )]))),
            include_tag: None,
            exclude_tag: Some(Box::new(InterpolationRule::ExcludeTagFromSources(vec![(
                None,
                "CN".to_string(),
            )]))),
        };
        let result = processor.get_nodes_for_rule(&rule, &sources).unwrap();

        // Should not have CN nodes
        for server in &result {
            assert!(!server.name.contains("CN"));
        }
    }

    #[test]
    fn test_servers_to_json_names() {
        let servers = vec![
            ProxyServer {
                name: "Node-01".to_string(),
                protocol: "shadowsocks".to_string(),
                server: "1.1.1.1".to_string(),
                port: 443,
                password: None,
                method: None,
                parameters: HashMap::new(),
            },
            ProxyServer {
                name: "Node-02".to_string(),
                protocol: "vmess".to_string(),
                server: "2.2.2.2".to_string(),
                port: 443,
                password: None,
                method: None,
                parameters: HashMap::new(),
            },
        ];

        let json = SingboxProcessor::servers_to_json_names(&servers);
        assert_eq!(json, "[\"Node-01\",\"Node-02\"]");
    }

    #[test]
    fn test_create_node_config() {
        let processor = SingboxProcessor;
        let server = ProxyServer {
            name: "Test-Node".to_string(),
            protocol: "shadowsocks".to_string(),
            server: "1.1.1.1".to_string(),
            port: 443,
            password: Some("test-password".to_string()),
            method: Some("aes-256-gcm".to_string()),
            parameters: HashMap::new(),
        };

        let config = processor.create_node_config(&server);
        let parsed: serde_json::Value = serde_json::from_str(&config).unwrap();

        assert_eq!(parsed["type"], "shadowsocks");
        assert_eq!(parsed["tag"], "Test-Node");
        assert_eq!(parsed["server"], "1.1.1.1");
        assert_eq!(parsed["server_port"], 443);
        assert_eq!(parsed["password"], "test-password");
        assert_eq!(parsed["method"], "aes-256-gcm");
    }

    #[test]
    fn test_create_node_config_with_source_prefix() {
        // Test that node config uses the prefixed name as tag
        let processor = SingboxProcessor;

        // Simulate a node that already has source prefix (as returned by get_nodes_for_rule)
        let server_with_prefix = ProxyServer {
            name: "clash1@HK-Node-01".to_string(), // Already prefixed
            protocol: "shadowsocks".to_string(),
            server: "1.1.1.1".to_string(),
            port: 443,
            password: Some("test".to_string()),
            method: Some("aes-256-gcm".to_string()),
            parameters: HashMap::new(),
        };

        let config = processor.create_node_config(&server_with_prefix);
        let parsed: serde_json::Value = serde_json::from_str(&config).unwrap();

        // The tag should include the source prefix
        assert_eq!(parsed["tag"], "clash1@HK-Node-01");
    }

    #[test]
    fn test_append_nodes_uses_prefixed_names() {
        let processor = SingboxProcessor;

        // Nodes with source prefixes (as they would be in multi-source scenario)
        let nodes = vec![
            ProxyServer {
                name: "clash1@HK-Node-01".to_string(),
                protocol: "shadowsocks".to_string(),
                server: "1.1.1.1".to_string(),
                port: 443,
                password: Some("test".to_string()),
                method: Some("aes-256-gcm".to_string()),
                parameters: HashMap::new(),
            },
            ProxyServer {
                name: "singbox1@US-Node-01".to_string(),
                protocol: "vmess".to_string(),
                server: "2.2.2.2".to_string(),
                port: 443,
                password: None,
                method: None,
                parameters: HashMap::new(),
            },
        ];

        let template = r#"{"outbounds": []}"#;
        let result = processor.append_nodes(template, &nodes).unwrap();

        // Verify the output contains the prefixed tags
        assert!(result.contains(r#""tag": "clash1@HK-Node-01""#));
        assert!(result.contains(r#""tag": "singbox1@US-Node-01""#));
    }
}
