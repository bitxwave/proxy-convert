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
        let is_vless = node.protocol == "vless";
        let is_hysteria2 = node.protocol == "hysteria2";
        let is_hysteria = node.protocol == "hysteria";
        let is_tuic = node.protocol == "tuic";
        let is_wireguard = node.protocol == "wireguard";
        // Snell uses `psk` (in extras), not `password`; suppress Clash's
        // generic-branch `password` insert so we don't duplicate the value
        // under a key mihomo doesn't read for snell.
        let is_snell = node.protocol == "snell";

        // For Clash, shadowsocks type should be "ss" and socks should be "socks5".
        let protocol_type = if node.protocol == "shadowsocks" {
            "ss".to_string()
        } else if node.protocol == "socks" {
            "socks5".to_string()
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
        } else if is_vless {
            self.convert_vless_params_to_clash(&mut config, node);
        } else if is_hysteria2 {
            self.convert_hysteria2_params_to_clash(&mut config, node);
        } else if is_hysteria {
            self.convert_hysteria_params_to_clash(&mut config, node);
        } else if is_tuic {
            self.convert_tuic_params_to_clash(&mut config, node);
        } else if is_wireguard {
            self.convert_wireguard_params_to_clash(&mut config, node);
        } else {
            // Generic handling for other protocols
            if let Some(method) = &node.method {
                config.insert(
                    "cipher".to_string(),
                    serde_json::Value::String(method.clone()),
                );
            }

            // Snell uses `psk`, not `password`; ProxyParams::Snell already
            // carries it via extras. Inserting `password` would duplicate the
            // value under a key mihomo doesn't read for snell.
            if let Some(password) = &node.password {
                if !is_snell {
                    config.insert(
                        "password".to_string(),
                        serde_json::Value::String(password.clone()),
                    );
                }
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

    /// Convert VLESS parameters to Clash (mihomo) format.
    fn convert_vless_params_to_clash(
        &self,
        config: &mut serde_json::Map<String, serde_json::Value>,
        node: &ProxyServer,
    ) {
        let params = &node.extras();

        if let crate::protocols::ProxyParams::Vless { uuid, flow, .. } = &node.params {
            config.insert("uuid".to_string(), serde_json::Value::String(uuid.clone()));
            if let Some(f) = flow {
                config.insert("flow".to_string(), serde_json::Value::String(f.clone()));
            }
        }
        config.insert("udp".to_string(), serde_json::Value::Bool(true));

        // packet-encoding
        if let Some(pe) = params.get("packet_encoding").or_else(|| params.get("packet-encoding")) {
            config.insert("packet-encoding".to_string(), pe.clone());
        }

        // TLS
        if let Some(tls) = params.get("tls") {
            if let Some(tls_obj) = tls.as_object() {
                let enabled = tls_obj.get("enabled").and_then(|v| v.as_bool()).unwrap_or(false);
                if enabled || tls_obj.contains_key("reality") {
                    config.insert("tls".to_string(), serde_json::Value::Bool(true));
                    if let Some(sn) = tls_obj.get("server_name") {
                        config.insert("servername".to_string(), sn.clone());
                    }
                    if let Some(insecure) = tls_obj.get("insecure") {
                        config.insert("skip-cert-verify".to_string(), insecure.clone());
                    }
                    if let Some(alpn) = tls_obj.get("alpn") {
                        config.insert("alpn".to_string(), alpn.clone());
                    }
                    if let Some(reality) = tls_obj.get("reality").and_then(|r| r.as_object()) {
                        let mut reality_opts = serde_json::Map::new();
                        if let Some(pk) = reality.get("public_key") {
                            reality_opts.insert("public-key".to_string(), pk.clone());
                        }
                        if let Some(sid) = reality.get("short_id") {
                            reality_opts.insert("short-id".to_string(), sid.clone());
                        }
                        config.insert(
                            "reality-opts".to_string(),
                            serde_json::Value::Object(reality_opts),
                        );
                    }
                    if let Some(utls) = tls_obj.get("utls").and_then(|u| u.as_object()) {
                        if let Some(fp) = utls.get("fingerprint") {
                            config.insert("client-fingerprint".to_string(), fp.clone());
                        }
                    }
                }
            } else if tls.as_bool().unwrap_or(false) {
                config.insert("tls".to_string(), serde_json::Value::Bool(true));
            }
        } else {
            // Already-flat Clash params; pass through.
            for k in ["servername", "sni", "skip-cert-verify", "alpn", "fingerprint", "client-fingerprint"] {
                if let Some(v) = params.get(k) {
                    config.insert(k.to_string(), v.clone());
                }
            }
        }

        // Transport
        if let Some(transport) = params.get("transport") {
            crate::protocols::transport_converter::singbox_transport_to_clash(config, transport);
        } else if let Some(network) = params.get("network") {
            // Pass-through Clash flat transport keys.
            config.insert("network".to_string(), network.clone());
            for k in ["ws-opts", "grpc-opts", "h2-opts", "http-opts"] {
                if let Some(v) = params.get(k) {
                    config.insert(k.to_string(), v.clone());
                }
            }
        }
    }

    /// Convert Hysteria2 parameters to Clash (mihomo) format.
    fn convert_hysteria2_params_to_clash(
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
        config.insert("udp".to_string(), serde_json::Value::Bool(true));

        if let crate::protocols::ProxyParams::Hysteria2 {
            obfs,
            obfs_password,
            up_mbps,
            down_mbps,
            ..
        } = &node.params
        {
            if let Some(o) = obfs {
                config.insert("obfs".to_string(), serde_json::Value::String(o.clone()));
            }
            if let Some(pw) = obfs_password {
                config.insert(
                    "obfs-password".to_string(),
                    serde_json::Value::String(pw.clone()),
                );
            }
            if let Some(up) = up_mbps {
                config.insert("up".to_string(), serde_json::Value::String(format!("{} Mbps", up)));
            }
            if let Some(down) = down_mbps {
                config.insert(
                    "down".to_string(),
                    serde_json::Value::String(format!("{} Mbps", down)),
                );
            }
        }

        // TLS via shared converter.
        if let Some(tls) = params.get("tls") {
            crate::protocols::transport_converter::singbox_tls_to_clash(config, tls);
        } else {
            for k in ["sni", "skip-cert-verify", "alpn", "fingerprint"] {
                if let Some(v) = params.get(k) {
                    config.insert(k.to_string(), v.clone());
                }
            }
        }
    }

    /// Convert Hysteria v1 parameters to Clash (mihomo) format.
    fn convert_hysteria_params_to_clash(
        &self,
        config: &mut serde_json::Map<String, serde_json::Value>,
        node: &ProxyServer,
    ) {
        let params = &node.extras();
        // Hysteria v1 uses auth-str instead of password.
        config.insert("udp".to_string(), serde_json::Value::Bool(true));

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
                    "auth-str".to_string(),
                    serde_json::Value::String(a.clone()),
                );
            }
            if let Some(o) = obfs {
                config.insert("obfs".to_string(), serde_json::Value::String(o.clone()));
            }
            if let Some(up) = up_mbps {
                config.insert("up".to_string(), serde_json::Value::String(format!("{} Mbps", up)));
            }
            if let Some(down) = down_mbps {
                config.insert(
                    "down".to_string(),
                    serde_json::Value::String(format!("{} Mbps", down)),
                );
            }
        }

        for (snake, kebab) in [
            ("recv_window_conn", "recv-window-conn"),
            ("recv_window", "recv-window"),
            ("disable_mtu_discovery", "disable_mtu_discovery"),
        ] {
            if let Some(v) = params.get(snake).or_else(|| params.get(kebab)) {
                config.insert(kebab.to_string(), v.clone());
            }
        }

        if let Some(tls) = params.get("tls") {
            crate::protocols::transport_converter::singbox_tls_to_clash(config, tls);
        } else {
            for k in ["sni", "skip-cert-verify", "alpn", "fingerprint"] {
                if let Some(v) = params.get(k) {
                    config.insert(k.to_string(), v.clone());
                }
            }
        }
    }

    /// Convert TUIC v5 parameters to Clash (mihomo) format.
    fn convert_tuic_params_to_clash(
        &self,
        config: &mut serde_json::Map<String, serde_json::Value>,
        node: &ProxyServer,
    ) {
        let params = &node.extras();
        config.insert("udp".to_string(), serde_json::Value::Bool(true));

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
            if let Some(p) = &node.password {
                config.insert(
                    "password".to_string(),
                    serde_json::Value::String(p.clone()),
                );
            }
            if let Some(cc) = congestion_control {
                config.insert(
                    "congestion-controller".to_string(),
                    serde_json::Value::String(cc.clone()),
                );
            }
            if let Some(udp) = udp_relay_mode {
                config.insert(
                    "udp-relay-mode".to_string(),
                    serde_json::Value::String(udp.clone()),
                );
            }
            if let Some(rtt) = zero_rtt_handshake {
                config.insert(
                    "reduce-rtt".to_string(),
                    serde_json::Value::Bool(*rtt),
                );
            }
            if let Some(hb) = heartbeat {
                // strip "ms" suffix if present
                let val = if let Some(n) = hb.strip_suffix("ms").and_then(|s| s.parse::<u64>().ok()) {
                    serde_json::Value::Number(n.into())
                } else {
                    serde_json::Value::String(hb.clone())
                };
                config.insert("heartbeat-interval".to_string(), val);
            }
        }

        if let Some(tls) = params.get("tls") {
            crate::protocols::transport_converter::singbox_tls_to_clash(config, tls);
            if let Some(disable_sni) = tls.get("disable_sni") {
                config.insert("disable-sni".to_string(), disable_sni.clone());
            }
            if let Some(utls) = tls.get("utls").and_then(|u| u.as_object()) {
                if let Some(fp) = utls.get("fingerprint") {
                    config.insert("client-fingerprint".to_string(), fp.clone());
                }
            }
        } else {
            for k in ["sni", "skip-cert-verify", "alpn", "disable-sni", "fingerprint", "client-fingerprint"] {
                if let Some(v) = params.get(k) {
                    config.insert(k.to_string(), v.clone());
                }
            }
        }
    }

    /// Convert WireGuard parameters to Clash (mihomo) format.
    /// Always emits the simplified form when there's exactly one peer.
    fn convert_wireguard_params_to_clash(
        &self,
        config: &mut serde_json::Map<String, serde_json::Value>,
        node: &ProxyServer,
    ) {
        // Drop generic password key if any was carried over.
        config.remove("password");
        config.insert("udp".to_string(), serde_json::Value::Bool(true));

        if let crate::protocols::ProxyParams::WireGuard {
            private_key,
            local_addresses,
            mtu,
            peers,
            ..
        } = &node.params
        {
            config.insert(
                "private-key".to_string(),
                serde_json::Value::String(private_key.clone()),
            );
            // Split combined local_addresses back into ip / ipv6.
            for addr in local_addresses {
                let host = addr.split('/').next().unwrap_or(addr);
                if host.contains(':') {
                    config
                        .entry("ipv6".to_string())
                        .or_insert(serde_json::Value::String(host.to_string()));
                } else {
                    config
                        .entry("ip".to_string())
                        .or_insert(serde_json::Value::String(host.to_string()));
                }
            }
            if let Some(m) = mtu {
                config.insert("mtu".to_string(), serde_json::Value::Number((*m).into()));
            }

            if peers.len() == 1 {
                // Simplified form — top-level peer fields override server/port we already wrote.
                let p = &peers[0];
                config.insert(
                    "server".to_string(),
                    serde_json::Value::String(p.server.clone()),
                );
                config.insert(
                    "port".to_string(),
                    serde_json::Value::Number(p.server_port.into()),
                );
                config.insert(
                    "public-key".to_string(),
                    serde_json::Value::String(p.public_key.clone()),
                );
                if let Some(psk) = &p.pre_shared_key {
                    config.insert(
                        "pre-shared-key".to_string(),
                        serde_json::Value::String(psk.clone()),
                    );
                }
                if !p.allowed_ips.is_empty() {
                    config.insert(
                        "allowed-ips".to_string(),
                        serde_json::Value::Array(
                            p.allowed_ips
                                .iter()
                                .map(|s| serde_json::Value::String(s.clone()))
                                .collect(),
                        ),
                    );
                }
                if let Some(reserved) = &p.reserved {
                    config.insert("reserved".to_string(), reserved.clone());
                }
            } else if !peers.is_empty() {
                // Full form — peers list. Drop server/port we wrote earlier.
                config.remove("server");
                config.remove("port");
                let peers_arr: Vec<serde_json::Value> = peers
                    .iter()
                    .map(|p| {
                        let mut po = serde_json::Map::new();
                        po.insert("server".to_string(), serde_json::Value::String(p.server.clone()));
                        po.insert("port".to_string(), serde_json::Value::Number(p.server_port.into()));
                        po.insert(
                            "public-key".to_string(),
                            serde_json::Value::String(p.public_key.clone()),
                        );
                        if let Some(psk) = &p.pre_shared_key {
                            po.insert(
                                "pre-shared-key".to_string(),
                                serde_json::Value::String(psk.clone()),
                            );
                        }
                        if !p.allowed_ips.is_empty() {
                            po.insert(
                                "allowed-ips".to_string(),
                                serde_json::Value::Array(
                                    p.allowed_ips
                                        .iter()
                                        .map(|s| serde_json::Value::String(s.clone()))
                                        .collect(),
                                ),
                            );
                        }
                        if let Some(reserved) = &p.reserved {
                            po.insert("reserved".to_string(), reserved.clone());
                        }
                        serde_json::Value::Object(po)
                    })
                    .collect();
                config.insert("peers".to_string(), serde_json::Value::Array(peers_arr));
            }
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
