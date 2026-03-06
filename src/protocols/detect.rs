//! Format detection for proxy configuration content.
//!
//! Detects clash, singbox, v2ray, subscription (base64), and plain text formats
//! without parsing full content. Used by ProtocolRegistry and TemplateEngine.

use crate::core::error::Result;
use serde_json::Value as JsonValue;

/// Detect content format. Returns (format_key, description) or None if unknown.
pub fn detect_format(content: &str) -> Result<Option<(String, String)>> {
    let content = content.trim();

    if let Ok(json_value) = serde_json::from_str::<JsonValue>(content) {
        if is_clash_format(&json_value) {
            return Ok(Some((
                "clash".to_string(),
                "Clash configuration".to_string(),
            )));
        }
        if is_singbox_format(&json_value) {
            return Ok(Some((
                "singbox".to_string(),
                "Sing-box configuration".to_string(),
            )));
        }
        if is_v2ray_format(&json_value) {
            return Ok(Some((
                "v2ray".to_string(),
                "V2Ray configuration".to_string(),
            )));
        }
    }

    if let Ok(yaml_value) = serde_yaml::from_str::<JsonValue>(content) {
        if is_clash_format(&yaml_value) {
            return Ok(Some((
                "clash".to_string(),
                "Clash configuration (YAML)".to_string(),
            )));
        }
        if is_singbox_format(&yaml_value) {
            return Ok(Some((
                "singbox".to_string(),
                "Sing-box configuration (YAML)".to_string(),
            )));
        }
        if is_v2ray_format(&yaml_value) {
            return Ok(Some((
                "v2ray".to_string(),
                "V2Ray configuration (YAML)".to_string(),
            )));
        }
    }

    if is_subscription_format(content) {
        return Ok(Some((
            "subscription".to_string(),
            "Subscription format (base64)".to_string(),
        )));
    }

    if is_plain_text_format(content) {
        return Ok(Some((
            "plain".to_string(),
            "Plain text format".to_string(),
        )));
    }

    Ok(None)
}

pub fn is_clash_format(json: &JsonValue) -> bool {
    json.get("port").is_some()
        || json.get("socks-port").is_some()
        || json.get("mixed-port").is_some()
        || json.get("external-controller").is_some()
        || json.get("proxies").is_some()
        || json.get("proxy-groups").is_some()
}

pub fn is_singbox_format(json: &JsonValue) -> bool {
    let has_singbox_fields = json.get("experimental").is_some()
        || json.get("dns").is_some()
        || json.get("route").is_some();

    has_singbox_fields
        || (json.get("log").is_some()
            && json.get("inbounds").is_some()
            && json.get("outbounds").is_some()
            && json.get("routing").is_none())
}

pub fn is_v2ray_format(json: &JsonValue) -> bool {
    let has_v2ray_fields = json.get("routing").is_some()
        || json.get("api").is_some()
        || json.get("stats").is_some();

    has_v2ray_fields
        || (json.get("log").is_some()
            && json.get("inbounds").is_some()
            && json.get("outbounds").is_some()
            && json.get("routing").is_some())
}

pub fn is_subscription_format(content: &str) -> bool {
    content.starts_with("vmess://")
        || content.starts_with("trojan://")
        || content.starts_with("ss://")
        || content.starts_with("ssr://")
        || content.starts_with("http://")
        || content.starts_with("https://")
        || is_base64_encoded(content)
}

pub fn is_plain_text_format(content: &str) -> bool {
    let lines: Vec<&str> = content.lines().collect();
    if lines.len() < 2 {
        return false;
    }
    lines.iter().take(3).any(|line| {
        let line = line.trim();
        !line.is_empty()
            && !line.starts_with('#')
            && (line.starts_with("vmess://")
                || line.starts_with("trojan://")
                || line.starts_with("ss://")
                || line.starts_with("ssr://")
                || line.starts_with("http://")
                || line.starts_with("https://"))
    })
}

pub fn is_base64_encoded(s: &str) -> bool {
    let trimmed: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    if trimmed.is_empty() || trimmed.len() % 4 != 0 {
        return false;
    }
    let base64_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";
    trimmed.chars().all(|c| base64_chars.contains(c))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_clash_json() {
        let content = r#"{"port": 7890, "proxies": []}"#;
        let r = detect_format(content).unwrap();
        assert_eq!(r.as_ref().map(|(k, _)| k.as_str()), Some("clash"));
    }

    #[test]
    fn test_detect_singbox_json() {
        let content = r#"{"log": {}, "inbounds": [], "outbounds": []}"#;
        let r = detect_format(content).unwrap();
        assert_eq!(r.as_ref().map(|(k, _)| k.as_str()), Some("singbox"));
    }

    #[test]
    fn test_detect_subscription_prefix() {
        let content = "vmess://abc@host:443#name";
        let r = detect_format(content).unwrap();
        assert_eq!(r.as_ref().map(|(k, _)| k.as_str()), Some("subscription"));
    }

    #[test]
    fn test_is_base64_encoded() {
        assert!(is_base64_encoded("YWJj")); // abc
        assert!(!is_base64_encoded("ab"));
        assert!(!is_base64_encoded("!!!"));
    }
}
