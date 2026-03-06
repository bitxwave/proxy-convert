//! Clash default template

/// Generate default Clash configuration template
pub fn generate() -> String {
    r#"mixed-port: 7890
allow-lan: true
bind-address: '*'
mode: rule
log-level: info
ipv6: true
external-controller: ':9090'
external-ui: dashboard
secret: 123456
tun:
  enable: true
  stack: system
  auto-route: true
  auto-detect-interface: true

dns:
  enable: true
  listen: '0.0.0.0:53'
  ipv6: true
  default-nameserver: [223.5.5.5, 114.114.114.114, 8.8.8.8]
  enhanced-mode: fake-ip
  fake-ip-range: 198.18.0.1/16
  fake-ip-filter: ['*.lan', '*.linksys.com', '*.linksyssmartwifi.com', swscan.apple.com, mesu.apple.com, '*.msftconnecttest.com', '*.msftncsi.com', 'time.*.com', 'time.*.gov', 'time.*.edu.cn', 'time.*.apple.com', 'time1.*.com', 'time2.*.com', 'time3.*.com', 'time4.*.com', 'time5.*.com', 'time6.*.com', 'time7.*.com', 'ntp.*.com', 'ntp.*.com', 'ntp1.*.com', 'ntp2.*.com', 'ntp3.*.com', 'ntp4.*.com', 'ntp5.*.com', 'ntp6.*.com', 'ntp7.*.com', '*.time.edu.cn', '*.ntp.org.cn', +.pool.ntp.org, time1.cloud.tencent.com, +.music.163.com, '*.126.net', musicapi.taihe.com, music.taihe.com, songsearch.kugou.com, trackercdn.kugou.com, '*.kuwo.cn', api-jooxtt.sanook.com, api.joox.com, joox.com, +.y.qq.com, +.music.tc.qq.com, aqqmusic.tc.qq.com, +.stream.qqmusic.qq.com, '*.xiami.com', +.music.migu.cn, +.srv.nintendo.net, +.stun.playstation.net, 'xbox.*.microsoft.com', +.xboxlive.com, localhost.ptlogin2.qq.com, proxy.golang.org, 'stun.*.*', 'stun.*.*.*', '+.stun.*.*.*.*', heartbeat.belkin.com, '*.linksys.com', '*.linksyssmartwifi.com', '*.router.asus.com', mesu.apple.com, swscan.apple.com, swquery.apple.com, swdownload.apple.com, swcdn.apple.com, swdist.apple.com, lens.l.google.com, stun.l.google.com, +.nflxvideo.net, '*.square-enix.com', '*.finalfantasyxiv.com', '*.ffxiv.com', '*.mcdn.bilivideo.cn']
  nameserver: ['https://doh.pub/dns-query', 'https://doh.dns.sb/dns-query', 'https://dns.adguard.com/dns-query', 'https://cdn-doh.ssnm.xyz/dns-query', 223.5.5.5, 180.76.76.76, 119.29.29.29, 117.50.11.11, 117.50.10.10, 114.114.114.114, 'https://dns.alidns.com/dns-query', 'https://doh.360.cn/dns-query']
  fallback: ['https://dns.quad9.net:5053/dns-query', 'https://dns-unfiltered.adguard.com/dns-query', 'https://doh.opendns.com/dns-query', 'https://1.0.0.1/dns-query', 'https://public.dns.iij.jp/dns-query', 'https://dns.twnic.tw/dns-query', 8.8.8.8, 1.1.1.1, 'tls://dns.rubyfish.cn:853', 'tls://1.0.0.1:853', 'tls://dns.google:853', 'https://dns.rubyfish.cn/dns-query', 'https://cloudflare-dns.com/dns-query', 'https://dns.google/dns-query']
  fallback-filter: { geoip: true, ipcidr: [0.0.0.0/8, 10.0.0.0/8, 100.64.0.0/10, 127.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12, 192.0.0.0/24, 192.0.2.0/24, 192.88.99.0/24, 192.168.0.0/16, 198.18.0.0/15, 198.51.100.0/24, 203.0.113.0/24, 224.0.0.0/4, 240.0.0.0/4, 255.255.255.255/32], domain: [+.google.com, +.facebook.com, +.youtube.com, +.freegfw.top, +.gogocloud.top, +.tgcloud.top, +.githubusercontent.com, +.googlevideo.com] }

proxies: []

proxy-groups:
  - name: '🚀 Select'
    type: select
    url: http://www.gstatic.com/generate_204
    interval: 600
    proxies:
      - '🚀 Manual'
      - '♻️ Auto'
      - '🔯 Fallback'
      - '🔮 LoadBalance'

  - name: '🚀 Manual'
    type: select
    url: http://www.gstatic.com/generate_204
    interval: 600
    proxies:
      - "{{ALL-TAG}}"

  - name: '♻️ Auto'
    type: url-test
    url: http://www.gstatic.com/generate_204
    interval: 600
    tolerance: 150
    proxies:
      - "{{ALL-TAG}}"

  - name: '🔯 Fallback'
    type: fallback
    url: http://www.gstatic.com/generate_204
    interval: 600
    proxies:
      - "{{ALL-TAG}}"

  - name: '🔮 LoadBalance'
    type: load-balance
    url: http://www.gstatic.com/generate_204
    interval: 600
    proxies:
      - "{{ALL-TAG}}"

rule-providers:
  reject:
    type: http
    behavior: domain
    url: 'https://raw.githubusercontent.com/Loyalsoldier/clash-rules/release/reject.txt'
    path: ./ruleset/reject.yaml
    interval: 86400
  icloud:
    type: http
    behavior: domain
    url: 'https://raw.githubusercontent.com/Loyalsoldier/clash-rules/release/icloud.txt'
    path: ./ruleset/icloud.yaml
    interval: 86400
  apple:
    type: http
    behavior: domain
    url: 'https://raw.githubusercontent.com/Loyalsoldier/clash-rules/release/apple.txt'
    path: ./ruleset/apple.yaml
    interval: 86400
  google:
    type: http
    behavior: domain
    url: 'https://raw.githubusercontent.com/Loyalsoldier/clash-rules/release/google.txt'
    path: ./ruleset/google.yaml
    interval: 86400
  proxy:
    type: http
    behavior: domain
    url: 'https://raw.githubusercontent.com/Loyalsoldier/clash-rules/release/proxy.txt'
    path: ./ruleset/proxy.yaml
    interval: 86400
  direct:
    type: http
    behavior: domain
    url: 'https://raw.githubusercontent.com/Loyalsoldier/clash-rules/release/direct.txt'
    path: ./ruleset/direct.yaml
    interval: 86400
  private:
    type: http
    behavior: domain
    url: 'https://raw.githubusercontent.com/Loyalsoldier/clash-rules/release/private.txt'
    path: ./ruleset/private.yaml
    interval: 86400
  gfw:
    type: http
    behavior: domain
    url: 'https://raw.githubusercontent.com/Loyalsoldier/clash-rules/release/gfw.txt'
    path: ./ruleset/gfw.yaml
    interval: 86400
  greatfire:
    type: http
    behavior: domain
    url: 'https://raw.githubusercontent.com/Loyalsoldier/clash-rules/release/greatfire.txt'
    path: ./ruleset/greatfire.yaml
    interval: 86400
  tld-not-cn:
    type: http
    behavior: domain
    url: 'https://raw.githubusercontent.com/Loyalsoldier/clash-rules/release/tld-not-cn.txt'
    path: ./ruleset/tld-not-cn.yaml
    interval: 86400
  telegramcidr:
    type: http
    behavior: ipcidr
    url: 'https://raw.githubusercontent.com/Loyalsoldier/clash-rules/release/telegramcidr.txt'
    path: ./ruleset/telegramcidr.yaml
    interval: 86400
  cncidr:
    type: http
    behavior: ipcidr
    url: 'https://raw.githubusercontent.com/Loyalsoldier/clash-rules/release/cncidr.txt'
    path: ./ruleset/cncidr.yaml
    interval: 86400
  lancidr:
    type: http
    behavior: ipcidr
    url: 'https://raw.githubusercontent.com/Loyalsoldier/clash-rules/release/lancidr.txt'
    path: ./ruleset/lancidr.yaml
    interval: 86400
  applications:
    type: http
    behavior: classical
    url: 'https://raw.githubusercontent.com/Loyalsoldier/clash-rules/release/applications.txt'
    path: ./ruleset/applications.yaml
    interval: 86400
rules:
  - DOMAIN-SUFFIX,<subscription_url>,DIRECT
  - RULE-SET,applications,DIRECT
  - RULE-SET,private,DIRECT
  - RULE-SET,reject,REJECT
  - RULE-SET,icloud,DIRECT
  - RULE-SET,apple,DIRECT
  - RULE-SET,google,🚀 Select
  - RULE-SET,proxy,🚀 Select
  - RULE-SET,direct,DIRECT
  - RULE-SET,lancidr,DIRECT,no-resolve
  - RULE-SET,cncidr,DIRECT,no-resolve
  - RULE-SET,telegramcidr,🚀 Select,no-resolve
  - GEOIP,LAN,DIRECT,no-resolve
  - GEOIP,CN,DIRECT,no-resolve
  - MATCH,🚀 Select
"#
    .to_string()
}
