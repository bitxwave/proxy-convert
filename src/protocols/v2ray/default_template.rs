//! V2Ray default template

/// Generate default V2Ray configuration template
pub fn generate() -> String {
    let template = serde_json::json!({
        "log": {
            "loglevel": "warning"
        },
        "inbounds": [
            {
                "port": 10808,
                "listen": "127.0.0.1",
                "protocol": "socks",
                "sniffing": {
                    "enabled": true,
                    "destOverride": ["http", "tls"]
                },
                "settings": {
                    "udp": true
                }
            },
            {
                "port": 10809,
                "listen": "127.0.0.1",
                "protocol": "http",
                "sniffing": {
                    "enabled": true,
                    "destOverride": ["http", "tls"]
                }
            }
        ],
        "outbounds": [
            {
                "tag": "proxy",
                "protocol": "vmess",
                "settings": {
                    "vnext": "{{ALL-TAG}}"
                },
                "streamSettings": {
                    "network": "tcp"
                }
            },
            {
                "tag": "direct",
                "protocol": "freedom",
                "settings": {}
            },
            {
                "tag": "block",
                "protocol": "blackhole",
                "settings": {}
            }
        ],
        "routing": {
            "domainStrategy": "IPIfNonMatch",
            "rules": [
                {
                    "type": "field",
                    "ip": ["geoip:private", "geoip:cn"],
                    "outboundTag": "direct"
                },
                {
                    "type": "field",
                    "domain": ["geosite:cn"],
                    "outboundTag": "direct"
                }
            ]
        },
        "dns": {
            "servers": [
                "8.8.8.8",
                "1.1.1.1",
                {
                    "address": "223.5.5.5",
                    "port": 53,
                    "domains": ["geosite:cn"]
                }
            ]
        }
    });

    serde_json::to_string_pretty(&template).unwrap_or_default()
}

