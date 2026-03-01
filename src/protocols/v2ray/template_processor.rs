//! V2Ray template processor

use crate::protocols::{ProtocolProcessor, ProxyServer};
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
        // V2Ray uses the same rule processing logic
        let processor = crate::protocols::singbox::template_processor::SingboxProcessor;
        processor.process_rule(rule, sources)
    }

    fn get_nodes_for_rule(
        &self,
        rule: &InterpolationRule,
        sources: &IndexMap<String, Source>,
    ) -> Result<Vec<ProxyServer>> {
        // V2Ray uses the same node extraction logic
        let processor = crate::protocols::singbox::template_processor::SingboxProcessor;
        processor.get_nodes_for_rule(rule, sources)
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
        // V2Ray uses "outbounds" array like Sing-box
        let processor = crate::protocols::singbox::template_processor::SingboxProcessor;
        processor.append_nodes(template, nodes)
    }

    fn create_node_config(&self, node: &ProxyServer) -> String {
        // V2Ray has different node structure
        let mut config = serde_json::Map::new();

        config.insert(
            "tag".to_string(),
            serde_json::Value::String(node.name.clone()),
        );
        config.insert(
            "protocol".to_string(),
            serde_json::Value::String(node.protocol.clone()),
        );

        // V2Ray structure is more complex, this is a simplified version
        for (key, value) in &node.parameters {
            config.insert(key.clone(), value.clone());
        }

        serde_json::to_string_pretty(&serde_json::Value::Object(config)).unwrap()
    }
}

