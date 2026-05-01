//! Template processing utility module
//!
//! This module is responsible for:
//! 1. Parsing templates and identifying protocol types
//! 2. Finding interpolation rules in templates
//! 3. Executing rules using protocol-specific processors
//! 4. Outputting the final result

use super::interpolation_parser::InterpolationParser;
use crate::protocols::{ProtocolProcessor, ProtocolRegistry, ProxyServer};
use crate::core::error::{ConvertError, Result};
use crate::protocols::source::Source;
use indexmap::IndexMap;

/// Template engine
pub struct TemplateEngine {
    /// Sources stored in insertion order using IndexMap
    sources: IndexMap<String, Source>,
}

impl TemplateEngine {
    /// Create new template engine
    pub fn new() -> Self {
        Self {
            sources: IndexMap::new(),
        }
    }

    /// Add source with complete source information.
    /// Unnamed sources get `source_N` (1-based) so multiple unnamed sources
    /// don't silently overwrite each other under a shared "default" key.
    pub fn add_source(&mut self, source: Source) {
        let key = match source.meta.name.as_deref() {
            Some(name) if !name.is_empty() => name.to_string(),
            _ => format!("source_{}", self.sources.len() + 1),
        };
        self.sources.insert(key, source);
    }

    /// Process template interpolation using the given registry for format detection and processor lookup.
    pub fn process_template(&self, template: &str, registry: &ProtocolRegistry) -> Result<String> {
        // Step 1: Identify protocol type from template (use registry's format detection)
        let protocol_type = Self::identify_protocol(template, registry)?;

        // Step 2: Get processor from registry
        let processor = registry
            .get_processor(&protocol_type)
            .ok_or_else(|| {
                ConvertError::ConfigValidationError(format!(
                    "Unsupported protocol type: {}",
                    protocol_type
                ))
            })?;

        // Step 3: Parse template as JSON or YAML
        let mut config: serde_json::Value = crate::utils::parse_helpers::to_json_value(template)?;

        // Step 4: Process interpolation rules in JSON structure
        let mut all_nodes = Vec::new();
        self.process_json_value(&mut config, processor, &mut all_nodes)?;

        // Step 5: Process default field using protocol-specific processor
        let unique_nodes = self.deduplicate_nodes(&all_nodes);
        let mut result = serde_json::to_string_pretty(&config).map_err(|e| {
            ConvertError::ConfigValidationError(format!("Failed to serialize config: {}", e))
        })?;
        result = processor.set_default_values(&result, &unique_nodes)?;

        // Step 6: Append all nodes using protocol-specific processor
        if !unique_nodes.is_empty() {
            result = processor.append_nodes(&result, &unique_nodes)?;
        }

        Ok(result)
    }

    /// Recursively process JSON value and expand interpolation rules
    fn process_json_value(
        &self,
        value: &mut serde_json::Value,
        processor: &dyn ProtocolProcessor,
        all_nodes: &mut Vec<ProxyServer>,
    ) -> Result<()> {
        match value {
            serde_json::Value::Array(arr) => {
                // Process array: expand interpolation rules in place
                let mut new_arr: Vec<serde_json::Value> = Vec::new();

                for item in arr.iter() {
                    if let serde_json::Value::String(s) = item {
                        if s.starts_with("{{") && s.ends_with("}}") {
                            match InterpolationParser::parse(s) {
                                Ok(rule) => {
                                    match processor.get_nodes_for_rule(&rule, &self.sources) {
                                        Ok(nodes) => {
                                            all_nodes.extend(nodes.clone());
                                            for node in &nodes {
                                                new_arr.push(serde_json::Value::String(
                                                    node.name.clone(),
                                                ));
                                            }
                                            continue;
                                        }
                                        Err(e) => {
                                            tracing::warn!(
                                                "Failed to get nodes for rule '{}': {}",
                                                s,
                                                e
                                            );
                                        }
                                    }
                                }
                                Err(e) => {
                                    tracing::warn!(
                                        "Failed to parse interpolation rule '{}': {}",
                                        s,
                                        e
                                    );
                                }
                            }
                        }
                    }
                    let mut item_clone = item.clone();
                    self.process_json_value(&mut item_clone, processor, all_nodes)?;
                    new_arr.push(item_clone);
                }

                // Deduplicate: track all seen names, preserve first occurrence
                let mut seen_names: std::collections::HashSet<String> =
                    std::collections::HashSet::new();
                let mut final_arr = Vec::new();

                for value in new_arr {
                    if let serde_json::Value::String(name) = &value {
                        // For string values, deduplicate by name
                        if seen_names.insert(name.clone()) {
                            final_arr.push(value);
                        }
                        // If already seen, skip
                    } else {
                        // Non-string values (objects, etc.) are always kept
                        final_arr.push(value);
                    }
                }

                *arr = final_arr;
            }
            serde_json::Value::Object(obj) => {
                // Process object: recurse into values, with special handling for "default" field
                for (key, v) in obj.iter_mut() {
                    if key == "default" {
                        // Special handling for "default" field
                        if let serde_json::Value::String(s) = v {
                            if s.starts_with("{{") && s.ends_with("}}") {
                                // Check if it's {{ALL-TAG}} - warn about it
                                let is_all_tag = s.contains("ALL-TAG")
                                    && !s.contains("INCLUDE-TAG")
                                    && !s.contains("EXCLUDE-TAG");

                                if is_all_tag {
                                    tracing::warn!(
                                        "Using {{{{ALL-TAG}}}} in 'default' field is not recommended. \
                                        Consider using a specific filter like {{{{INCLUDE-TAG:...}}}} or {{{{EXCLUDE-TAG:...}}}}. \
                                        Will use the first matched node."
                                    );
                                }

                                match InterpolationParser::parse(s) {
                                    Ok(rule) => {
                                        match processor
                                            .get_nodes_for_rule(&rule, &self.sources)
                                        {
                                            Ok(nodes) => {
                                                all_nodes.extend(nodes.clone());
                                                if !nodes.is_empty() {
                                                    *s = nodes[0].name.clone();
                                                }
                                            }
                                            Err(e) => {
                                                tracing::warn!(
                                                    "Failed to get nodes for default rule '{}': {}",
                                                    s,
                                                    e
                                                );
                                            }
                                        }
                                    }
                                    Err(e) => {
                                        tracing::warn!(
                                            "Failed to parse default interpolation '{}': {}",
                                            s,
                                            e
                                        );
                                    }
                                }
                            }
                        }
                    } else {
                        self.process_json_value(v, processor, all_nodes)?;
                    }
                }
            }
            serde_json::Value::String(s) => {
                if s.starts_with("{{") && s.ends_with("}}") {
                    match InterpolationParser::parse(s) {
                        Ok(rule) => {
                            match processor.get_nodes_for_rule(&rule, &self.sources) {
                                Ok(nodes) => {
                                    all_nodes.extend(nodes.clone());
                                    if !nodes.is_empty() {
                                        *s = nodes[0].name.clone();
                                    }
                                }
                                Err(e) => {
                                    tracing::warn!(
                                        "Failed to get nodes for rule '{}': {}",
                                        s,
                                        e
                                    );
                                }
                            }
                        }
                        Err(e) => {
                            tracing::warn!(
                                "Failed to parse interpolation rule '{}': {}",
                                s,
                                e
                            );
                        }
                    }
                }
            }
            _ => {}
        }
        Ok(())
    }

    /// Identify protocol type from template content using registry's format detection.
    fn identify_protocol(template: &str, registry: &ProtocolRegistry) -> Result<String> {
        if let Ok(Some((format, _))) = registry.auto_detect_format(template) {
            return Ok(format);
        }
        // Default to singbox if cannot detect
        Ok("singbox".to_string())
    }

    /// Deduplicate nodes
    fn deduplicate_nodes(&self, nodes: &[ProxyServer]) -> Vec<ProxyServer> {
        let mut unique_nodes = Vec::new();
        let mut seen_names = std::collections::HashSet::new();

        for node in nodes {
            if !seen_names.contains(&node.name) {
                seen_names.insert(node.name.clone());
                unique_nodes.push(node.clone());
            }
        }

        unique_nodes
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::template::interpolation_parser::InterpolationRule;

    #[test]
    fn test_interpolation_parser_all_tag() {
        // Test basic interpolation rule parsing
        assert!(matches!(
            InterpolationParser::parse("{{ALL-TAG}}").unwrap(),
            InterpolationRule::AllTagFromSources(_)
        ));

        assert!(matches!(
            InterpolationParser::parse("{{ALL-TAG:clash1}}").unwrap(),
            InterpolationRule::AllTagFromSources(_)
        ));

        assert!(matches!(
            InterpolationParser::parse("{{ALL-TAG:clash1,singbox1}}").unwrap(),
            InterpolationRule::AllTagFromSources(_)
        ));
    }

    #[test]
    fn test_interpolation_parser_include_tag() {
        // Test tag filtering rules
        assert!(matches!(
            InterpolationParser::parse("{{INCLUDE-TAG:US,JP}}").unwrap(),
            InterpolationRule::IncludeTagFromSources(_)
        ));

        assert!(matches!(
            InterpolationParser::parse("{{INCLUDE-TAG:clash1@US,JP}}").unwrap(),
            InterpolationRule::IncludeTagFromSources(_)
        ));
    }

    #[test]
    fn test_interpolation_parser_exclude_tag() {
        assert!(matches!(
            InterpolationParser::parse("{{EXCLUDE-TAG:CN,AD}}").unwrap(),
            InterpolationRule::ExcludeTagFromSources(_)
        ));

        assert!(matches!(
            InterpolationParser::parse("{{EXCLUDE-TAG:clash1@CN,AD}}").unwrap(),
            InterpolationRule::ExcludeTagFromSources(_)
        ));
    }

    #[test]
    fn test_interpolation_parser_combined_rules() {
        // Test combined rules
        assert!(matches!(
            InterpolationParser::parse("{{ALL-TAG;INCLUDE-TAG:US,JP}}").unwrap(),
            InterpolationRule::CombinedRule { .. }
        ));

        assert!(matches!(
            InterpolationParser::parse("{{INCLUDE-TAG:US,JP;EXCLUDE-TAG:CN,AD}}").unwrap(),
            InterpolationRule::CombinedRule { .. }
        ));
    }

    #[test]
    fn test_interpolation_parser_multi_source() {
        // Test complex multi-source rules
        let rule = "{{INCLUDE-TAG:clash1@US,JP,clash2@HK,clash3@SG}}";
        let parsed = InterpolationParser::parse(rule).unwrap();
        match parsed {
            InterpolationRule::IncludeTagFromSources(source_tag_pairs) => {
                // Verify includes all expected tags
                let tags: Vec<String> = source_tag_pairs
                    .iter()
                    .map(|(_, tag)| tag.clone())
                    .collect();
                assert!(tags.contains(&"US".to_string()));
                assert!(tags.contains(&"JP".to_string()));
                assert!(tags.contains(&"HK".to_string()));
                assert!(tags.contains(&"SG".to_string()));
            }
            _ => panic!("Expected IncludeTagFromSources"),
        }
    }

}
