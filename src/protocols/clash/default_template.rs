//! Clash default template

/// Generate default Clash configuration template
pub fn generate() -> String {
    r#"mixed-port: 7890
allow-lan: true
bind-address: '*'
mode: rule
log-level: info
external-controller: '0.0.0.0:9090'

dns:
  enable: true
  listen: 0.0.0.0:53
  enhanced-mode: fake-ip
  fake-ip-range: 198.18.0.1/16
  nameserver:
    - 223.5.5.5
    - 119.29.29.29
  fallback:
    - 8.8.8.8
    - 1.1.1.1
  fallback-filter:
    geoip: true
    geoip-code: CN

proxies: "{{ALL-TAG}}"

proxy-groups:
  - name: Proxy
    type: select
    proxies:
      - Auto
      - DIRECT
      - "{{ALL-TAG}}"

  - name: Auto
    type: url-test
    url: 'https://www.gstatic.com/generate_204'
    interval: 300
    proxies:
      - "{{ALL-TAG}}"

rules:
  - GEOIP,LAN,DIRECT
  - GEOIP,CN,DIRECT
  - MATCH,Proxy
"#
    .to_string()
}
