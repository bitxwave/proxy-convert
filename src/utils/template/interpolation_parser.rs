use crate::core::error::{ConvertError, Result};

/// Interpolation rule types
#[derive(Debug, Clone, PartialEq)]
pub enum InterpolationRule {
    /// Insert all nodes from specified sources (or all sources if none specified)
    /// Vec contains (source_name, tag_filter) pairs where source_name is optional
    AllTagFromSources(Vec<(Option<String>, Option<String>)>),

    /// Insert nodes matching tags from sources
    /// Vec contains (source_name, tag) pairs where source_name is optional
    IncludeTagFromSources(Vec<(Option<String>, String)>),

    /// Exclude nodes matching tags from sources
    /// Vec contains (source_name, tag) pairs where source_name is optional
    ExcludeTagFromSources(Vec<(Option<String>, String)>),

    /// Combined rules: support arbitrary order of multiple rules
    CombinedRule {
        all_tag: Option<Box<InterpolationRule>>,
        include_tag: Option<Box<InterpolationRule>>,
        exclude_tag: Option<Box<InterpolationRule>>,
    },
}

/// Interpolation rule parser
pub struct InterpolationParser;

impl InterpolationParser {
    /// Parse interpolation rule string
    ///
    /// Supported formats:
    /// - `{{ALL-TAG}}` - Get all nodes from all sources
    /// - `{{ALL-TAG:source1}}` - Get all nodes from specified source
    /// - `{{ALL-TAG:source1,source2}}` - Get all nodes from multiple sources
    /// - `{{INCLUDE-TAG:tag1,tag2}}` - Include nodes matching tags
    /// - `{{INCLUDE-TAG:source@tag1,tag2}}` - Include nodes matching tags from source
    /// - `{{EXCLUDE-TAG:tag1,tag2}}` - Exclude nodes matching tags
    /// - `{{ALL-TAG;EXCLUDE-TAG:CN}}` - Combined rules separated by semicolon
    pub fn parse(rule: &str) -> Result<InterpolationRule> {
        let rule: &str = rule.trim();

        // Extract rule content (remove double braces)
        if !rule.starts_with("{{") || !rule.ends_with("}}") {
            return Err(ConvertError::ConfigValidationError(format!(
                "Interpolation rule must be wrapped with {{}}: {}",
                rule
            )));
        }

        let rule_expr: &str = &rule[2..rule.len() - 2];

        if rule_expr.trim().is_empty() {
            return Err(ConvertError::ConfigValidationError(
                "Empty interpolation rule".to_string(),
            ));
        }

        Self::parse_combined_rule(rule_expr)
    }

    /// Parse combined rule (multiple sub-rules separated by semicolon)
    fn parse_combined_rule(rule_expr: &str) -> Result<InterpolationRule> {
        let rule_exprs = Self::split_rule_expr(rule_expr);

        if rule_exprs.is_empty() {
            return Err(ConvertError::ConfigValidationError(
                "Empty combined rule".to_string(),
            ));
        }

        // If only one rule, return it directly (not wrapped in CombinedRule)
        if rule_exprs.len() == 1 {
            return Self::parse_single_rule(rule_exprs[0]);
        }

        // Multiple rules - parse each and combine
        let mut all_tag = None;
        let mut include_tag = None;
        let mut exclude_tag = None;

        for rule_expr in rule_exprs {
            if rule_expr.is_empty() {
                continue;
            }

            let parsed = Self::parse_single_rule(rule_expr)?;

            match &parsed {
                InterpolationRule::AllTagFromSources(_) => {
                    all_tag = Some(Box::new(parsed));
                }
                InterpolationRule::IncludeTagFromSources(_) => {
                    include_tag = Some(Box::new(parsed));
                }
                InterpolationRule::ExcludeTagFromSources(_) => {
                    exclude_tag = Some(Box::new(parsed));
                }
                InterpolationRule::CombinedRule { .. } => {
                    // Nested combined rules are not allowed
                    return Err(ConvertError::ConfigValidationError(
                        "Nested combined rules are not supported".to_string(),
                    ));
                }
            }
        }

        Ok(InterpolationRule::CombinedRule {
            all_tag,
            include_tag,
            exclude_tag,
        })
    }

    /// Split rule expression by semicolons
    fn split_rule_expr(rule_expr: &str) -> Vec<&str> {
        let rule_expr = rule_expr.trim();
        if rule_expr.is_empty() {
            return Vec::new();
        }

        rule_expr
            .split(';')
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .collect()
    }

    /// Parse a single rule (without semicolons)
    fn parse_single_rule(rule: &str) -> Result<InterpolationRule> {
        let rule = rule.trim();

        // Split by colon to get rule type and parameters
        let colon_pos = rule.find(':');

        let (rule_type, params) = if let Some(pos) = colon_pos {
            (&rule[..pos], Some(&rule[pos + 1..]))
        } else {
            (rule, None)
        };

        let rule_type = rule_type.trim().to_uppercase();

        match rule_type.as_str() {
            "ALL-TAG" => Self::parse_all_tag_rule(params),
            "INCLUDE-TAG" => Self::parse_include_tag_rule(params),
            "EXCLUDE-TAG" => Self::parse_exclude_tag_rule(params),
            _ => Err(ConvertError::ConfigValidationError(format!(
                "Unknown interpolation rule type: {}",
                rule_type
            ))),
        }
    }

    /// Parse ALL-TAG rule
    /// Formats:
    /// - `ALL-TAG` - All nodes from all sources
    /// - `ALL-TAG:source1` - All nodes from source1
    /// - `ALL-TAG:source1,source2` - All nodes from source1 and source2
    fn parse_all_tag_rule(params: Option<&str>) -> Result<InterpolationRule> {
        let sources = match params {
            None | Some("") => {
                // No parameters - get all nodes from all sources
                vec![(None, None)]
            }
            Some(params) => {
                // Parse source list
                params
                    .split(',')
                    .map(|s| s.trim())
                    .filter(|s| !s.is_empty())
                    .map(|source| {
                        if source.contains('@') {
                            // Format: source@tag (for filtering within source)
                            let parts: Vec<&str> = source.splitn(2, '@').collect();
                            (
                                Some(parts[0].trim().to_string()),
                                Some(parts[1].trim().to_string()),
                            )
                        } else {
                            // Just source name
                            (Some(source.to_string()), None)
                        }
                    })
                    .collect()
            }
        };

        Ok(InterpolationRule::AllTagFromSources(sources))
    }

    /// Parse INCLUDE-TAG rule
    /// Formats:
    /// - `INCLUDE-TAG:tag1,tag2` - Include nodes with tag1 or tag2 from all sources
    /// - `INCLUDE-TAG:source@tag1,tag2` - Include nodes with tags from specific source
    fn parse_include_tag_rule(params: Option<&str>) -> Result<InterpolationRule> {
        let params = params.ok_or_else(|| {
            ConvertError::ConfigValidationError(
                "INCLUDE-TAG requires at least one tag parameter".to_string(),
            )
        })?;

        if params.trim().is_empty() {
            return Err(ConvertError::ConfigValidationError(
                "INCLUDE-TAG requires at least one tag parameter".to_string(),
            ));
        }

        let tag_pairs = Self::parse_source_tag_pairs(params);

        if tag_pairs.is_empty() {
            return Err(ConvertError::ConfigValidationError(
                "INCLUDE-TAG requires at least one tag parameter".to_string(),
            ));
        }

        Ok(InterpolationRule::IncludeTagFromSources(tag_pairs))
    }

    /// Parse EXCLUDE-TAG rule
    /// Formats:
    /// - `EXCLUDE-TAG:tag1,tag2` - Exclude nodes with tag1 or tag2
    /// - `EXCLUDE-TAG:source@tag1,tag2` - Exclude nodes with tags from specific source
    fn parse_exclude_tag_rule(params: Option<&str>) -> Result<InterpolationRule> {
        let params = params.ok_or_else(|| {
            ConvertError::ConfigValidationError(
                "EXCLUDE-TAG requires at least one tag parameter".to_string(),
            )
        })?;

        if params.trim().is_empty() {
            return Err(ConvertError::ConfigValidationError(
                "EXCLUDE-TAG requires at least one tag parameter".to_string(),
            ));
        }

        let tag_pairs = Self::parse_source_tag_pairs(params);

        if tag_pairs.is_empty() {
            return Err(ConvertError::ConfigValidationError(
                "EXCLUDE-TAG requires at least one tag parameter".to_string(),
            ));
        }

        Ok(InterpolationRule::ExcludeTagFromSources(tag_pairs))
    }

    /// Parse source@tag pairs from comma-separated string
    /// Supports formats:
    /// - `tag1,tag2` - Tags from all sources (no source specified)
    /// - `source@tag` - Tag from specific source
    /// - `source1@tag1,tag2,source2@tag3` - Mixed format (tag2 from all sources)
    ///
    /// Note: Tags without @ are always matched from ALL sources, no inheritance.
    fn parse_source_tag_pairs(params: &str) -> Vec<(Option<String>, String)> {
        let mut result = Vec::new();

        for item in params
            .split(',')
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
        {
            if item.contains('@') {
                // Format: source@tag - from specific source
                let parts: Vec<&str> = item.splitn(2, '@').collect();
                let source = parts[0].trim();
                let tag = parts[1].trim();

                if !tag.is_empty() {
                    let source_opt = if source.is_empty() {
                        None
                    } else {
                        Some(source.to_string())
                    };
                    result.push((source_opt, tag.to_string()));
                }
            } else {
                // No @ - match from all sources (no inheritance)
                result.push((None, item.to_string()));
            }
        }

        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_all_tag_basic() {
        // Test {{ALL-TAG}} - no parameters
        let result = InterpolationParser::parse("{{ALL-TAG}}").unwrap();
        match result {
            InterpolationRule::AllTagFromSources(sources) => {
                assert_eq!(sources.len(), 1);
                assert_eq!(sources[0], (None, None));
            }
            _ => panic!("Expected AllTagFromSources, got {:?}", result),
        }
    }

    #[test]
    fn test_all_tag_single_source() {
        // Test {{ALL-TAG:clash1}}
        let result = InterpolationParser::parse("{{ALL-TAG:clash1}}").unwrap();
        match result {
            InterpolationRule::AllTagFromSources(sources) => {
                assert_eq!(sources.len(), 1);
                assert_eq!(sources[0], (Some("clash1".to_string()), None));
            }
            _ => panic!("Expected AllTagFromSources"),
        }
    }

    #[test]
    fn test_all_tag_multiple_sources() {
        // Test {{ALL-TAG:clash1,singbox1}}
        let result = InterpolationParser::parse("{{ALL-TAG:clash1,singbox1}}").unwrap();
        match result {
            InterpolationRule::AllTagFromSources(sources) => {
                assert_eq!(sources.len(), 2);
                assert_eq!(sources[0], (Some("clash1".to_string()), None));
                assert_eq!(sources[1], (Some("singbox1".to_string()), None));
            }
            _ => panic!("Expected AllTagFromSources"),
        }
    }

    #[test]
    fn test_include_tag_basic() {
        // Test {{INCLUDE-TAG:US,JP}}
        let result = InterpolationParser::parse("{{INCLUDE-TAG:US,JP}}").unwrap();
        match result {
            InterpolationRule::IncludeTagFromSources(pairs) => {
                assert_eq!(pairs.len(), 2);
                assert_eq!(pairs[0], (None, "US".to_string()));
                assert_eq!(pairs[1], (None, "JP".to_string()));
            }
            _ => panic!("Expected IncludeTagFromSources"),
        }
    }

    #[test]
    fn test_include_tag_with_source() {
        // Test {{INCLUDE-TAG:clash1@US,JP}}
        // clash1@US -> from clash1
        // JP -> from all sources (no inheritance)
        let result = InterpolationParser::parse("{{INCLUDE-TAG:clash1@US,JP}}").unwrap();
        match result {
            InterpolationRule::IncludeTagFromSources(pairs) => {
                assert_eq!(pairs.len(), 2);
                assert_eq!(pairs[0], (Some("clash1".to_string()), "US".to_string()));
                assert_eq!(pairs[1], (None, "JP".to_string())); // JP from all sources
            }
            _ => panic!("Expected IncludeTagFromSources"),
        }
    }

    #[test]
    fn test_include_tag_multiple_sources() {
        // Test {{INCLUDE-TAG:clash1@US,singbox1@JP,singbox1@SG}}
        // Each tag must explicitly specify its source
        let result =
            InterpolationParser::parse("{{INCLUDE-TAG:clash1@US,singbox1@JP,singbox1@SG}}")
                .unwrap();
        match result {
            InterpolationRule::IncludeTagFromSources(pairs) => {
                assert_eq!(pairs.len(), 3);
                assert_eq!(pairs[0], (Some("clash1".to_string()), "US".to_string()));
                assert_eq!(pairs[1], (Some("singbox1".to_string()), "JP".to_string()));
                assert_eq!(pairs[2], (Some("singbox1".to_string()), "SG".to_string()));
            }
            _ => panic!("Expected IncludeTagFromSources"),
        }
    }

    #[test]
    fn test_exclude_tag_basic() {
        // Test {{EXCLUDE-TAG:CN,AD}}
        let result = InterpolationParser::parse("{{EXCLUDE-TAG:CN,AD}}").unwrap();
        match result {
            InterpolationRule::ExcludeTagFromSources(pairs) => {
                assert_eq!(pairs.len(), 2);
                assert_eq!(pairs[0], (None, "CN".to_string()));
                assert_eq!(pairs[1], (None, "AD".to_string()));
            }
            _ => panic!("Expected ExcludeTagFromSources"),
        }
    }

    #[test]
    fn test_exclude_tag_with_source() {
        // Test {{EXCLUDE-TAG:clash1@CN,AD}}
        // clash1@CN -> from clash1
        // AD -> from all sources (no inheritance)
        let result = InterpolationParser::parse("{{EXCLUDE-TAG:clash1@CN,AD}}").unwrap();
        match result {
            InterpolationRule::ExcludeTagFromSources(pairs) => {
                assert_eq!(pairs.len(), 2);
                assert_eq!(pairs[0], (Some("clash1".to_string()), "CN".to_string()));
                assert_eq!(pairs[1], (None, "AD".to_string())); // AD from all sources
            }
            _ => panic!("Expected ExcludeTagFromSources"),
        }
    }

    #[test]
    fn test_combined_rule() {
        // Test {{ALL-TAG;EXCLUDE-TAG:CN}}
        let result = InterpolationParser::parse("{{ALL-TAG;EXCLUDE-TAG:CN}}").unwrap();
        match result {
            InterpolationRule::CombinedRule {
                all_tag,
                include_tag,
                exclude_tag,
            } => {
                assert!(all_tag.is_some());
                assert!(include_tag.is_none());
                assert!(exclude_tag.is_some());
            }
            _ => panic!("Expected CombinedRule"),
        }
    }

    #[test]
    fn test_combined_rule_complex() {
        // Test {{INCLUDE-TAG:US,JP;EXCLUDE-TAG:CN,AD}}
        let result = InterpolationParser::parse("{{INCLUDE-TAG:US,JP;EXCLUDE-TAG:CN,AD}}").unwrap();
        match result {
            InterpolationRule::CombinedRule {
                all_tag,
                include_tag,
                exclude_tag,
            } => {
                assert!(all_tag.is_none());
                assert!(include_tag.is_some());
                assert!(exclude_tag.is_some());
            }
            _ => panic!("Expected CombinedRule"),
        }
    }

    #[test]
    fn test_error_empty_rule() {
        // Test {{}}
        let result = InterpolationParser::parse("{{}}");
        assert!(result.is_err());
    }

    #[test]
    fn test_error_invalid_format() {
        // Test without braces
        let result = InterpolationParser::parse("ALL-TAG");
        assert!(result.is_err());
    }

    #[test]
    fn test_error_unknown_rule() {
        // Test unknown rule type
        let result = InterpolationParser::parse("{{UNKNOWN-RULE:test}}");
        assert!(result.is_err());
    }

    #[test]
    fn test_error_include_tag_no_params() {
        // Test INCLUDE-TAG without parameters
        let result = InterpolationParser::parse("{{INCLUDE-TAG:}}");
        assert!(result.is_err());
    }

    #[test]
    fn test_case_insensitive() {
        // Test case insensitivity
        let result1 = InterpolationParser::parse("{{all-tag}}").unwrap();
        let result2 = InterpolationParser::parse("{{ALL-TAG}}").unwrap();
        let result3 = InterpolationParser::parse("{{All-Tag}}").unwrap();

        assert!(matches!(result1, InterpolationRule::AllTagFromSources(_)));
        assert!(matches!(result2, InterpolationRule::AllTagFromSources(_)));
        assert!(matches!(result3, InterpolationRule::AllTagFromSources(_)));
    }

    #[test]
    fn test_whitespace_handling() {
        // Test whitespace handling
        let result = InterpolationParser::parse("{{  ALL-TAG : clash1 , singbox1  }}").unwrap();
        match result {
            InterpolationRule::AllTagFromSources(sources) => {
                assert_eq!(sources.len(), 2);
            }
            _ => panic!("Expected AllTagFromSources"),
        }
    }

    #[test]
    fn test_trailing_semicolon() {
        // Test trailing semicolon (should be ignored)
        let result = InterpolationParser::parse("{{ALL-TAG;}}").unwrap();
        assert!(matches!(result, InterpolationRule::AllTagFromSources(_)));
    }
}
