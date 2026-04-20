//! Shared node resolution logic used by all protocol processors.

use crate::protocols::ProxyServer;
use crate::core::error::Result;
use crate::utils::source::parser::Source;
use crate::utils::template::interpolation_parser::InterpolationRule;
use indexmap::IndexMap;
use serde_json;

/// Shared node resolver that provides node-filtering and rule-processing
/// logic used by all protocol processors (Singbox, Clash, V2Ray).
pub struct SharedNodeResolver;

impl SharedNodeResolver {
    /// Process an interpolation rule and return the result as a JSON array of node names.
    pub fn process_rule(
        rule: &InterpolationRule,
        sources: &IndexMap<String, Source>,
    ) -> Result<String> {
        let servers = Self::get_nodes_for_rule(rule, sources)?;
        Ok(Self::servers_to_json_names(&servers))
    }

    /// Get nodes matching an interpolation rule from the given sources.
    pub fn get_nodes_for_rule(
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
                    Self::get_nodes_for_rule(all_rule, sources)?
                } else {
                    Self::get_all_servers_from_sources(sources)
                };

                // Apply INCLUDE-TAG filter (intersection)
                if let Some(include_rule) = include_tag {
                    let include_servers = Self::get_nodes_for_rule(include_rule, sources)?;
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

    /// Get all servers from sources (with source prefix if multiple sources).
    /// Uses IndexMap to preserve insertion order of sources.
    pub fn get_all_servers_from_sources(sources: &IndexMap<String, Source>) -> Vec<ProxyServer> {
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

    /// Get servers from specific source (with source prefix if multiple sources exist).
    pub fn get_servers_from_source(
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

    /// Filter servers by tag (name contains tag).
    pub fn filter_by_tag(servers: Vec<ProxyServer>, tag: &str) -> Vec<ProxyServer> {
        servers
            .into_iter()
            .filter(|s| s.name.contains(tag))
            .collect()
    }

    /// Convert server list to JSON array of names.
    pub fn servers_to_json_names(servers: &[ProxyServer]) -> String {
        let names: Vec<String> = servers.iter().map(|s| s.name.clone()).collect();
        serde_json::to_string(&names).unwrap_or_else(|_| "[]".to_string())
    }
}
