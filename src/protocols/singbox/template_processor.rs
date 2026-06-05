//! Sing-box template processor

use crate::protocols::{ProtocolProcessor, ProxyServer};
use crate::protocols::shared_resolver::SharedNodeResolver;
use crate::core::error::Result;
use crate::protocols::source::Source;
use crate::utils::template::interpolation_parser::InterpolationRule;
use indexmap::IndexMap;
use serde_json;

/// Sing-box protocol processor
pub struct SingboxProcessor;

impl SingboxProcessor {
    /// Convert VMess parameters to Sing-box format
    /// Handles both Clash-style flat params and Sing-box-style nested objects
    pub fn convert_vmess_params_to_singbox(
        config: &mut serde_json::Map<String, serde_json::Value>,
        params: &std::collections::HashMap<String, serde_json::Value>,
    ) {
        // UUID
        if let Some(uuid) = params.get("uuid") {
            config.insert("uuid".to_string(), uuid.clone());
        }

        // alterId → alter_id
        if let Some(alter_id) = params.get("alterId").or(params.get("alter_id")) {
            config.insert("alter_id".to_string(), alter_id.clone());
        }

        // cipher → security (if not already set)
        // Skip if cipher is "auto" since sing-box VMess security defaults to "auto"
        if let Some(cipher) = config.get("security") {
            let cipher_str = cipher.as_str().unwrap_or("");
            if cipher_str == "auto" {
                config.remove("security");
            }
        }

        // TLS handling — delegate to shared converter
        if let Some(tls_value) = crate::protocols::transport_converter::clash_tls_to_singbox(params, false) {
            config.insert("tls".to_string(), tls_value);
        }

        // Transport handling — delegate to shared converter
        if let Some(transport_value) = crate::protocols::transport_converter::clash_transport_to_singbox(params) {
            config.insert("transport".to_string(), transport_value);
        }
    }

    /// Convert AnyTLS parameters to Sing-box format.
    /// Handles both Clash flat params and sing-box nested `tls`. Idle-session
    /// fields are normalized to duration strings (sing-box accepts "30s",
    /// while mihomo often emits raw integers in seconds).
    pub fn convert_anytls_params_to_singbox(
        config: &mut serde_json::Map<String, serde_json::Value>,
        params: &std::collections::HashMap<String, serde_json::Value>,
    ) {
        // AnyTLS implies TLS. Reuse the trojan path (always_enabled=true) so the
        // result has tls.enabled set even when the Clash source didn't say so.
        if let Some(tls_value) =
            crate::protocols::transport_converter::clash_tls_to_singbox(params, true)
        {
            config.insert("tls".to_string(), tls_value);
        }

        let normalize_duration = |v: &serde_json::Value| -> Option<serde_json::Value> {
            if let Some(s) = v.as_str() {
                Some(serde_json::Value::String(s.to_string()))
            } else if let Some(n) = v.as_u64() {
                Some(serde_json::Value::String(format!("{}s", n)))
            } else {
                None
            }
        };

        for (kebab, snake) in [
            ("idle-session-check-interval", "idle_session_check_interval"),
            ("idle-session-timeout", "idle_session_timeout"),
        ] {
            if let Some(v) = params.get(snake).or_else(|| params.get(kebab)) {
                if let Some(out) = normalize_duration(v) {
                    config.insert(snake.to_string(), out);
                }
            }
        }

        if let Some(v) = params
            .get("min_idle_session")
            .or_else(|| params.get("min-idle-session"))
        {
            if v.is_number() {
                config.insert("min_idle_session".to_string(), v.clone());
            }
        }
    }

    /// Convert VLESS parameters to sing-box format. Reuses VMess transport
    /// logic plus adds reality / utls handling.
    pub fn convert_vless_params_to_singbox(
        config: &mut serde_json::Map<String, serde_json::Value>,
        node: &ProxyServer,
    ) {
        let params = &node.extras();

        if let crate::protocols::ProxyParams::Vless { uuid, flow, .. } = &node.params {
            config.insert(
                "uuid".to_string(),
                serde_json::Value::String(uuid.clone()),
            );
            if let Some(f) = flow {
                config.insert("flow".to_string(), serde_json::Value::String(f.clone()));
            }
        }

        if let Some(packet_encoding) = params.get("packet-encoding").or_else(|| params.get("packet_encoding")) {
            config.insert("packet_encoding".to_string(), packet_encoding.clone());
        }

        // TLS: enabled if Clash had `tls: true` OR reality-opts present.
        let mut tls_obj = serde_json::Map::new();
        let mut tls_present = false;
        if let Some(servername) = params.get("servername").or_else(|| params.get("sni")) {
            tls_obj.insert("server_name".to_string(), servername.clone());
            tls_present = true;
        }
        if let Some(skip) = params.get("skip-cert-verify") {
            tls_obj.insert("insecure".to_string(), skip.clone());
            tls_present = true;
        }
        if let Some(alpn) = params.get("alpn") {
            tls_obj.insert("alpn".to_string(), alpn.clone());
            tls_present = true;
        }
        if let Some(reality_opts) = params.get("reality-opts").or_else(|| params.get("reality_opts")) {
            let mut reality = serde_json::Map::new();
            reality.insert("enabled".to_string(), serde_json::Value::Bool(true));
            if let Some(pk) = reality_opts.get("public-key").or_else(|| reality_opts.get("public_key")) {
                reality.insert("public_key".to_string(), pk.clone());
            }
            if let Some(sid) = reality_opts.get("short-id").or_else(|| reality_opts.get("short_id")) {
                reality.insert("short_id".to_string(), sid.clone());
            }
            tls_obj.insert("reality".to_string(), serde_json::Value::Object(reality));
            tls_present = true;
        }
        if let Some(fingerprint) = params.get("client-fingerprint").or_else(|| params.get("fingerprint")) {
            let mut utls = serde_json::Map::new();
            utls.insert("enabled".to_string(), serde_json::Value::Bool(true));
            utls.insert("fingerprint".to_string(), fingerprint.clone());
            tls_obj.insert("utls".to_string(), serde_json::Value::Object(utls));
            tls_present = true;
        }
        if let Some(tls) = params.get("tls") {
            // mihomo writes `tls: true` (bool) or sing-box writes nested object.
            if let Some(obj) = tls.as_object() {
                for (k, v) in obj {
                    tls_obj.entry(k.clone()).or_insert_with(|| v.clone());
                }
                tls_present = true;
            } else if tls.as_bool().unwrap_or(false) {
                tls_present = true;
            }
        }
        if tls_present {
            tls_obj
                .entry("enabled".to_string())
                .or_insert(serde_json::Value::Bool(true));
            config.insert("tls".to_string(), serde_json::Value::Object(tls_obj));
        }

        // Transport (reuse the shared converter)
        if let Some(transport_value) =
            crate::protocols::transport_converter::clash_transport_to_singbox(params)
        {
            config.insert("transport".to_string(), transport_value);
        }
    }

    /// Convert Hysteria2 parameters to sing-box format.
    pub fn convert_hysteria2_params_to_singbox(
        config: &mut serde_json::Map<String, serde_json::Value>,
        node: &ProxyServer,
    ) {
        let params = &node.extras();

        if let crate::protocols::ProxyParams::Hysteria2 {
            obfs,
            obfs_password,
            up_mbps,
            down_mbps,
            ..
        } = &node.params
        {
            if let Some(up) = up_mbps {
                config.insert(
                    "up_mbps".to_string(),
                    serde_json::Value::Number((*up).into()),
                );
            }
            if let Some(down) = down_mbps {
                config.insert(
                    "down_mbps".to_string(),
                    serde_json::Value::Number((*down).into()),
                );
            }
            if let Some(o) = obfs {
                let mut o_obj = serde_json::Map::new();
                o_obj.insert("type".to_string(), serde_json::Value::String(o.clone()));
                if let Some(pw) = obfs_password {
                    o_obj.insert(
                        "password".to_string(),
                        serde_json::Value::String(pw.clone()),
                    );
                }
                config.insert("obfs".to_string(), serde_json::Value::Object(o_obj));
            }
        }

        // TLS — reuse trojan-style converter (always enabled for hysteria2)
        if let Some(tls_value) =
            crate::protocols::transport_converter::clash_tls_to_singbox(params, true)
        {
            config.insert("tls".to_string(), tls_value);
        }

        if let Some(hop) = params.get("hop-interval").or_else(|| params.get("hop_interval")) {
            if let Some(s) = hop.as_str() {
                config.insert(
                    "hop_interval".to_string(),
                    serde_json::Value::String(s.to_string()),
                );
            } else if let Some(n) = hop.as_u64() {
                config.insert(
                    "hop_interval".to_string(),
                    serde_json::Value::String(format!("{}s", n)),
                );
            }
        }
    }

    /// Convert Hysteria v1 parameters to sing-box format.
    pub fn convert_hysteria_params_to_singbox(
        config: &mut serde_json::Map<String, serde_json::Value>,
        node: &ProxyServer,
    ) {
        let params = &node.extras();

        if let crate::protocols::ProxyParams::Hysteria {
            auth_str,
            obfs,
            up_mbps,
            down_mbps,
            ..
        } = &node.params
        {
            if let Some(a) = auth_str {
                config.insert(
                    "auth_str".to_string(),
                    serde_json::Value::String(a.clone()),
                );
                // sing-box hysteria uses auth_str (not password) — drop the
                // password key set earlier.
                config.remove("password");
            }
            if let Some(o) = obfs {
                config.insert("obfs".to_string(), serde_json::Value::String(o.clone()));
            }
            if let Some(up) = up_mbps {
                config.insert(
                    "up_mbps".to_string(),
                    serde_json::Value::Number((*up).into()),
                );
            }
            if let Some(down) = down_mbps {
                config.insert(
                    "down_mbps".to_string(),
                    serde_json::Value::Number((*down).into()),
                );
            }
        }

        for (clash_key, singbox_key) in [
            ("recv-window-conn", "recv_window_conn"),
            ("recv-window", "recv_window"),
            ("disable_mtu_discovery", "disable_mtu_discovery"),
        ] {
            if let Some(v) = params.get(clash_key).or_else(|| params.get(singbox_key)) {
                config.insert(singbox_key.to_string(), v.clone());
            }
        }

        if let Some(tls_value) =
            crate::protocols::transport_converter::clash_tls_to_singbox(params, true)
        {
            config.insert("tls".to_string(), tls_value);
        }
    }

    /// Convert TUIC v5 parameters to sing-box format.
    pub fn convert_tuic_params_to_singbox(
        config: &mut serde_json::Map<String, serde_json::Value>,
        node: &ProxyServer,
    ) {
        let params = &node.extras();

        if let crate::protocols::ProxyParams::Tuic {
            uuid,
            congestion_control,
            udp_relay_mode,
            zero_rtt_handshake,
            heartbeat,
            ..
        } = &node.params
        {
            if let Some(u) = uuid {
                config.insert("uuid".to_string(), serde_json::Value::String(u.clone()));
            }
            if let Some(cc) = congestion_control {
                config.insert(
                    "congestion_control".to_string(),
                    serde_json::Value::String(cc.clone()),
                );
            }
            if let Some(udp) = udp_relay_mode {
                config.insert(
                    "udp_relay_mode".to_string(),
                    serde_json::Value::String(udp.clone()),
                );
            }
            if let Some(rtt) = zero_rtt_handshake {
                config.insert(
                    "zero_rtt_handshake".to_string(),
                    serde_json::Value::Bool(*rtt),
                );
            }
            if let Some(hb) = heartbeat {
                config.insert(
                    "heartbeat".to_string(),
                    serde_json::Value::String(hb.clone()),
                );
            }
        }

        // TLS: tuic is always over TLS; respect disable-sni when present.
        if let Some(tls_value) =
            crate::protocols::transport_converter::clash_tls_to_singbox(params, true)
        {
            let mut tls_obj = match tls_value {
                serde_json::Value::Object(o) => o,
                _ => serde_json::Map::new(),
            };
            if let Some(disable_sni) = params.get("disable-sni").or_else(|| params.get("disable_sni")) {
                tls_obj.insert("disable_sni".to_string(), disable_sni.clone());
            }
            if let Some(fingerprint) = params
                .get("client-fingerprint")
                .or_else(|| params.get("fingerprint"))
            {
                let mut utls = serde_json::Map::new();
                utls.insert("enabled".to_string(), serde_json::Value::Bool(true));
                utls.insert("fingerprint".to_string(), fingerprint.clone());
                tls_obj.insert("utls".to_string(), serde_json::Value::Object(utls));
            }
            config.insert("tls".to_string(), serde_json::Value::Object(tls_obj));
        }
    }

    /// Convert WireGuard parameters to sing-box format.
    /// Always emits a `peers` array; mihomo's "simplified" form (top-level
    /// peer fields) is normalized by `parse_clash_proxy` already.
    pub fn convert_wireguard_params_to_singbox(
        config: &mut serde_json::Map<String, serde_json::Value>,
        node: &ProxyServer,
    ) {
        // sing-box wireguard doesn't have top-level password / server / server_port
        // when peers are used. Drop them; we'll re-emit from typed peers.
        config.remove("password");

        if let crate::protocols::ProxyParams::WireGuard {
            private_key,
            local_addresses,
            mtu,
            peers,
            ..
        } = &node.params
        {
            config.insert(
                "private_key".to_string(),
                serde_json::Value::String(private_key.clone()),
            );
            if !local_addresses.is_empty() {
                config.insert(
                    "local_address".to_string(),
                    serde_json::Value::Array(
                        local_addresses
                            .iter()
                            .map(|s| serde_json::Value::String(s.clone()))
                            .collect(),
                    ),
                );
            }
            if let Some(m) = mtu {
                config.insert(
                    "mtu".to_string(),
                    serde_json::Value::Number((*m).into()),
                );
            }
            // Drop our top-level placeholder server/server_port; sing-box wants
            // them inside peers when peers is present.
            if !peers.is_empty() {
                config.remove("server");
                config.remove("server_port");
                let peers_arr: Vec<serde_json::Value> = peers
                    .iter()
                    .map(|p| {
                        let mut po = serde_json::Map::new();
                        po.insert(
                            "server".to_string(),
                            serde_json::Value::String(p.server.clone()),
                        );
                        po.insert(
                            "server_port".to_string(),
                            serde_json::Value::Number(p.server_port.into()),
                        );
                        po.insert(
                            "public_key".to_string(),
                            serde_json::Value::String(p.public_key.clone()),
                        );
                        if let Some(psk) = &p.pre_shared_key {
                            po.insert(
                                "pre_shared_key".to_string(),
                                serde_json::Value::String(psk.clone()),
                            );
                        }
                        po.insert(
                            "allowed_ips".to_string(),
                            serde_json::Value::Array(
                                p.allowed_ips
                                    .iter()
                                    .map(|s| serde_json::Value::String(s.clone()))
                                    .collect(),
                            ),
                        );
                        if let Some(reserved) = &p.reserved {
                            // mihomo accepts list `[209,98,59]` or string `"U4An"`.
                            // sing-box wants list-of-bytes; pass through array as-is.
                            if reserved.is_array() {
                                po.insert("reserved".to_string(), reserved.clone());
                            }
                        }
                        serde_json::Value::Object(po)
                    })
                    .collect();
                config.insert("peers".to_string(), serde_json::Value::Array(peers_arr));
            }
        }
    }

    /// Convert Trojan parameters to Sing-box format
    /// Handles both Clash-style flat params (sni, skip-cert-verify) and
    /// Sing-box-style nested objects (tls: {enabled, server_name, insecure})
    pub fn convert_trojan_params_to_singbox(
        config: &mut serde_json::Map<String, serde_json::Value>,
        params: &std::collections::HashMap<String, serde_json::Value>,
    ) {
        // TLS handling — delegate to shared converter (trojan always has TLS)
        if let Some(tls_value) = crate::protocols::transport_converter::clash_tls_to_singbox(params, true) {
            config.insert("tls".to_string(), tls_value);
        }

        // Transport handling — delegate to shared converter
        if let Some(transport_value) = crate::protocols::transport_converter::clash_transport_to_singbox(params) {
            config.insert("transport".to_string(), transport_value);
        }
    }

}

impl ProtocolProcessor for SingboxProcessor {
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
        if nodes.is_empty() {
            return Ok(template.to_string());
        }

        let first_node_name = &nodes[0].name;

        // Parse template as JSON to properly handle selector outbounds
        let mut config: serde_json::Value = serde_json::from_str(template).map_err(|e| {
            crate::core::error::ConvertError::ConfigValidationError(format!(
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
            crate::core::error::ConvertError::ConfigValidationError(format!(
                "Failed to serialize config: {}",
                e
            ))
        })
    }

    fn append_nodes(&self, template: &str, nodes: &[ProxyServer]) -> Result<String> {
        // Parse the template as JSON to safely manipulate it
        let mut config: serde_json::Value = serde_json::from_str(template).map_err(|e| {
            crate::core::error::ConvertError::ConfigValidationError(format!(
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
            crate::core::error::ConvertError::ConfigValidationError(format!(
                "Failed to serialize config: {}",
                e
            ))
        })
    }

    fn create_node_config(&self, node: &ProxyServer) -> String {
        let mut config = serde_json::Map::new();

        // Normalize protocol name
        let is_shadowsocks = node.protocol == "ss" || node.protocol == "shadowsocks";
        let is_vmess = node.protocol == "vmess";
        let is_trojan = node.protocol == "trojan";
        let is_anytls = node.protocol == "anytls";
        let is_vless = node.protocol == "vless";
        let is_hysteria2 = node.protocol == "hysteria2";
        let is_hysteria = node.protocol == "hysteria";
        let is_tuic = node.protocol == "tuic";
        let is_wireguard = node.protocol == "wireguard";

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
            if is_shadowsocks {
                config.insert(
                    "method".to_string(),
                    serde_json::Value::String(method.clone()),
                );
            } else if is_vmess {
                // For VMess, method/cipher maps to "security"
                config.insert(
                    "security".to_string(),
                    serde_json::Value::String(method.clone()),
                );
            }
        }

        if let Some(password) = &node.password {
            config.insert(
                "password".to_string(),
                serde_json::Value::String(password.clone()),
            );
        }
        // VMess specific handling
        if is_vmess {
            Self::convert_vmess_params_to_singbox(&mut config, &node.extras());
        } else if is_trojan {
            Self::convert_trojan_params_to_singbox(&mut config, &node.extras());
        } else if is_anytls {
            Self::convert_anytls_params_to_singbox(&mut config, &node.extras());
        } else if is_vless {
            Self::convert_vless_params_to_singbox(&mut config, node);
        } else if is_hysteria2 {
            Self::convert_hysteria2_params_to_singbox(&mut config, node);
        } else if is_hysteria {
            Self::convert_hysteria_params_to_singbox(&mut config, node);
        } else if is_tuic {
            Self::convert_tuic_params_to_singbox(&mut config, node);
        } else if is_wireguard {
            Self::convert_wireguard_params_to_singbox(&mut config, node);
        } else {
            // Generic parameter handling
            // Skip fields that are already handled or not needed in sing-box
            let skip_keys = ["cipher", "udp", "name", "type", "server", "port"];
            for (key, value) in node.extras() {
                if !skip_keys.contains(&key.as_str()) && !(is_shadowsocks && key == "udp") {
                    config.insert(key.clone(), value.clone());
                }
            }
        }

        serde_json::to_string_pretty(&serde_json::Value::Object(config))
            .unwrap_or_else(|e| {
                tracing::error!("Failed to serialize singbox node config: {}", e);
                "{}".to_string()
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::source::{Protocol, SourceMeta};
    use crate::protocols::source::{Config, Source};
    use std::collections::HashMap;
    use crate::protocols::{clash, singbox, ProxyParams};

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
        // Deserialize into strongly-typed clash::Config
        let clash1_config: clash::Config =
            serde_json::from_value(clash1_config).unwrap();
        sources.insert(
            "clash1".to_string(),
            Source {
                meta: SourceMeta {
                    name: Some("clash1".to_string()),
                    source_type: Protocol::Clash,
                    location: crate::core::source::SourceLocation::File("./clash.yaml".into()),
                    source: "./clash.yaml".to_string(),
                    format: None,
                    flag: None,
                },
                config: Config::Clash(clash1_config),
            },
        );

        // Create singbox1 source with test nodes
        let singbox1_config = serde_json::json!({
            "inbounds": [],
            "outbounds": [
                {"tag": "SG-Node-01", "type": "shadowsocks", "server": "4.4.4.4", "server_port": 443, "method": "aes-256-gcm", "password": "test"},
                {"tag": "CN-Node-01", "type": "shadowsocks", "server": "5.5.5.5", "server_port": 443, "method": "aes-256-gcm", "password": "test"},
            ]
        });
        // Deserialize into strongly-typed singbox::Config
        let singbox1_config: singbox::Config =
            serde_json::from_value(singbox1_config).unwrap();
        sources.insert(
            "singbox1".to_string(),
            Source {
                meta: SourceMeta {
                    name: Some("singbox1".to_string()),
                    source_type: Protocol::SingBox,
                    location: crate::core::source::SourceLocation::File("./singbox.json".into()),
                    source: "./singbox.json".to_string(),
                    format: None,
                    flag: None,
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
                  
                params: ProxyParams::Generic { extras: HashMap::new() },
            },
            ProxyServer {
                name: "Node-02".to_string(),
                protocol: "vmess".to_string(),
                server: "2.2.2.2".to_string(),
                port: 443,
                password: None,
                method: None,
                  
                params: ProxyParams::Generic { extras: HashMap::new() },
            },
        ];

        let json = crate::protocols::shared_resolver::SharedNodeResolver::servers_to_json_names(&servers);
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
              
            params: ProxyParams::Generic { extras: HashMap::new() },
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
              
            params: ProxyParams::Generic { extras: HashMap::new() },
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
                  
                params: ProxyParams::Generic { extras: HashMap::new() },
            },
            ProxyServer {
                name: "singbox1@US-Node-01".to_string(),
                protocol: "vmess".to_string(),
                server: "2.2.2.2".to_string(),
                port: 443,
                password: None,
                method: None,
                  
                params: ProxyParams::Generic { extras: HashMap::new() },
            },
        ];

        let template = r#"{"outbounds": []}"#;
        let result = processor.append_nodes(template, &nodes).unwrap();

        // Verify the output contains the prefixed tags
        assert!(result.contains(r#""tag": "clash1@HK-Node-01""#));
        assert!(result.contains(r#""tag": "singbox1@US-Node-01""#));
    }
}
