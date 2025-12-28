//! Clash template processor

use crate::protocols::{ProtocolProcessor, ProxyServer};
use crate::utils::error::Result;
use crate::utils::source::parser::Source;
use crate::utils::template::interpolation_parser::InterpolationRule;
use indexmap::IndexMap;
use regex::Regex;
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
        // Clash uses "proxies" array instead of "outbounds"
        let proxies_regex = Regex::new(r#""proxies"\s*:\s*\["#).unwrap();
        let mut result = template.to_string();

        if let Some(mat) = proxies_regex.find(template) {
            let start_pos = mat.end();
            let mut bracket_count = 1;
            let mut pos = start_pos;
            let chars: Vec<char> = result.chars().collect();

            while pos < chars.len() && bracket_count > 0 {
                match chars[pos] {
                    '[' => bracket_count += 1,
                    ']' => bracket_count -= 1,
                    _ => {}
                }
                pos += 1;
            }

            if bracket_count == 0 {
                let end_pos = pos - 1;
                let current_content = &result[start_pos..end_pos];
                let trimmed_content = current_content.trim();

                let mut new_proxies = String::new();

                if !trimmed_content.is_empty() && trimmed_content != "]" {
                    new_proxies.push_str(trimmed_content);
                    if !trimmed_content.ends_with(',') {
                        new_proxies.push(',');
                    }
                }

                for (i, node) in nodes.iter().enumerate() {
                    if i > 0 || !trimmed_content.is_empty() {
                        new_proxies.push('\n');
                    }

                    let node_config = self.create_node_config(node);
                    new_proxies.push_str(&node_config);

                    if i < nodes.len() - 1 {
                        new_proxies.push(',');
                    }
                }

                result.replace_range(start_pos..end_pos, &new_proxies);
            }
        }

        Ok(result)
    }

    fn create_node_config(&self, node: &ProxyServer) -> String {
        // Clash has different node structure
        let mut config = serde_json::Map::new();

        // Check if this is a shadowsocks node
        let is_shadowsocks = node.protocol == "shadowsocks" || node.protocol == "ss";

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

        // For shadowsocks nodes, always add udp: true (Clash requires explicit UDP setting)
        // When converting from sing-box SS to Clash SS, we need to add udp: true
        if is_shadowsocks {
            config.insert("udp".to_string(), serde_json::Value::Bool(true));
        }

        // Add other parameters (skip "udp" for shadowsocks as we've already set it)
        for (key, value) in &node.parameters {
            if !(is_shadowsocks && key == "udp") {
                config.insert(key.clone(), value.clone());
            }
        }

        serde_json::to_string_pretty(&serde_json::Value::Object(config)).unwrap()
    }
}
