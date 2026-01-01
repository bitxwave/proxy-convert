//! Sing-box default template

/// Generate default Sing-box configuration template
pub fn generate() -> String {
    let template = serde_json::json!({
        "log": {
            "level": "info",
            "timestamp": true
        },
        "dns": {
            "servers": [
                {
                    "tag": "local",
                    "address": "223.5.5.5",
                    "detour": "DIRECT"
                },
                {
                    "tag": "remote",
                    "address": "8.8.8.8",
                    "detour": "Proxy"
                }
            ],
            "final": "local",
            "strategy": "prefer_ipv4",
            "disable_cache": false,
            "disable_expire": false,
            "independent_cache": false,
            "reverse_mapping": false
        },
        "inbounds": [
            {
                "type": "tun",
                "tag": "TUN-IN",
                "address": ["198.18.0.1/16", "fd00:1::1/64"],
                "mtu": 9000,
                "stack": "mixed",
                "auto_route": true,
                "strict_route": true,
                "sniff": true,
                "sniff_override_destination": true,
                "endpoint_independent_nat": true
            }
        ],
        "outbounds": [
            {
                "tag": "DIRECT",
                "type": "direct"
            },
            {
                "tag": "REJECT",
                "type": "block"
            },
            {
                "tag": "Proxy",
                "type": "selector",
                "interrupt_exist_connections": true,
                "default": "Auto",
                "outbounds": ["Auto", "Manual"]
            },
            {
                "tag": "Auto",
                "type": "urltest",
                "url": "https://www.gstatic.com/generate_204",
                "interval": "3m",
                "tolerance": 50,
                "idle_timeout": "5m",
                "interrupt_exist_connections": true,
                "outbounds": ["{{ALL-TAG}}"]
            },
            {
                "tag": "Manual",
                "type": "selector",
                "interrupt_exist_connections": true,
                "default": "",
                "outbounds": ["{{ALL-TAG}}"]
            }
        ],
        "route": {
            "default_domain_resolver": {
                "server": "local"
            },
            "rules": [
                {"action": "sniff"},
                {"action": "hijack-dns", "protocol": "dns"},
                {"clash_mode": "global", "action": "route", "outbound": "Proxy"},
                {"clash_mode": "direct", "action": "route", "outbound": "DIRECT"},
                {"rule_set": "ads", "action": "reject", "method": "default", "no_drop": false},
                {
                    "rule_set": ["microsoft-cn", "games-cn", "network-test", "applications", "cn", "cn-ip", "private-ip", "private"],
                    "action": "route",
                    "outbound": "DIRECT"
                },
                {
                    "rule_set": ["proxy", "telegram-ip"],
                    "action": "route",
                    "outbound": "Proxy"
                }
            ],
            "rule_set": [
                {"tag": "ads", "type": "remote", "format": "binary", "url": "https://cdn.jsdelivr.net/gh/DustinWin/ruleset_geodata@sing-box-ruleset/ads.srs", "download_detour": "Proxy", "update_interval": "1d"},
                {"tag": "private", "type": "remote", "format": "binary", "url": "https://cdn.jsdelivr.net/gh/DustinWin/ruleset_geodata@sing-box-ruleset/private.srs", "download_detour": "Proxy", "update_interval": "1d"},
                {"tag": "microsoft-cn", "type": "remote", "format": "binary", "url": "https://cdn.jsdelivr.net/gh/DustinWin/ruleset_geodata@sing-box-ruleset/microsoft-cn.srs", "download_detour": "Proxy", "update_interval": "1d"},
                {"tag": "apple-cn", "type": "remote", "format": "binary", "url": "https://cdn.jsdelivr.net/gh/DustinWin/ruleset_geodata@sing-box-ruleset/apple-cn.srs", "download_detour": "Proxy", "update_interval": "1d"},
                {"tag": "google-cn", "type": "remote", "format": "binary", "url": "https://cdn.jsdelivr.net/gh/DustinWin/ruleset_geodata@sing-box-ruleset/google-cn.srs", "download_detour": "Proxy", "update_interval": "1d"},
                {"tag": "games-cn", "type": "remote", "format": "binary", "url": "https://cdn.jsdelivr.net/gh/DustinWin/ruleset_geodata@sing-box-ruleset/games-cn.srs", "download_detour": "Proxy", "update_interval": "1d"},
                {"tag": "network-test", "type": "remote", "format": "binary", "url": "https://cdn.jsdelivr.net/gh/DustinWin/ruleset_geodata@sing-box-ruleset/networktest.srs", "download_detour": "Proxy", "update_interval": "1d"},
                {"tag": "applications", "type": "remote", "format": "binary", "url": "https://cdn.jsdelivr.net/gh/DustinWin/ruleset_geodata@sing-box-ruleset/applications.srs", "download_detour": "Proxy", "update_interval": "1d"},
                {"tag": "proxy", "type": "remote", "format": "binary", "url": "https://cdn.jsdelivr.net/gh/DustinWin/ruleset_geodata@sing-box-ruleset/proxy.srs", "download_detour": "Proxy", "update_interval": "1d"},
                {"tag": "cn", "type": "remote", "format": "binary", "url": "https://cdn.jsdelivr.net/gh/DustinWin/ruleset_geodata@sing-box-ruleset/cn.srs", "download_detour": "Proxy", "update_interval": "1d"},
                {"tag": "telegram-ip", "type": "remote", "format": "binary", "url": "https://cdn.jsdelivr.net/gh/DustinWin/ruleset_geodata@sing-box-ruleset/telegramip.srs", "download_detour": "Proxy", "update_interval": "1d"},
                {"tag": "private-ip", "type": "remote", "format": "binary", "url": "https://cdn.jsdelivr.net/gh/DustinWin/ruleset_geodata@sing-box-ruleset/privateip.srs", "download_detour": "Proxy", "update_interval": "1d"},
                {"tag": "cn-ip", "type": "remote", "format": "binary", "url": "https://cdn.jsdelivr.net/gh/DustinWin/ruleset_geodata@sing-box-ruleset/cnip.srs", "download_detour": "Proxy", "update_interval": "1d"}
            ],
            "final": "Proxy",
            "auto_detect_interface": true
        },
        "experimental": {
            "cache_file": {
                "enabled": true,
                "path": "cache.db",
                "store_fakeip": false,
                "store_rdrc": false
            },
            "clash_api": {
                "external_controller": "0.0.0.0:9090",
                "external_ui": "dashboard",
                "external_ui_download_url": "https://github.com/MetaCubeX/Yacd-meta/archive/gh-pages.zip",
                "external_ui_download_detour": "Proxy",
                "default_mode": "rule"
            }
        }
    });

    serde_json::to_string_pretty(&template).unwrap_or_default()
}

