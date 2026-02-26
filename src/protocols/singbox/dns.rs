use super::common::base::{
    IpVersion, LogicalMode, Network, QueryType, SingleOrMultipleValue, Strategy, DialParams, NetworkType,
};
use super::common::tls;
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;
use indexmap::IndexMap;

#[skip_serializing_none]
#[derive(Default, Serialize, Deserialize, Debug, Clone)]
pub struct DNS {
    pub servers: Vec<Server>,
    pub rules: Option<Vec<Rule>>,
    pub r#final: Option<String>,
    pub strategy: Option<Strategy>,
    pub disable_cache: Option<bool>,
    pub disable_expire: Option<bool>,
    pub independent_cache: Option<bool>,
    pub cache_capacity: Option<u32>,
    pub reverse_mapping: Option<bool>,
    pub client_subnet: Option<String>,
}

/// Legacy DNS server format (deprecated in sing-box 1.12, removed in 1.14).
/// Uses `address` URL instead of `type` + `server`; see https://sing-box.sagernet.org/configuration/dns/server/legacy/
#[skip_serializing_none]
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct LegacyServer {
    pub tag: Option<String>,
    pub address: String,
    pub address_resolver: Option<String>,
    pub address_strategy: Option<String>,
    pub strategy: Option<String>,
    pub detour: Option<String>,
    pub client_subnet: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum Server {
    /// Empty or missing type => legacy format (address-based)
    #[serde(rename = "")]
    Legacy(LegacyServer),
    Local(LocalServer),
    Hosts(HostsServer),
    Tcp(TcpServer),
    Udp(UdpServer),
    Tls(TlsServer),
    Quic(QuicServer),
    Https(HttpsServer),
    H3(H3Server),
    Dhcp(DhcpServer),
    Fakeip(FakeIPServer),
    Tailscale(TailscaleServer),
    Resolved(ResolvedServer),
}

#[skip_serializing_none]
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct LocalServer {
    pub tag: String,
    pub prefer_go: Option<bool>,
    #[serde(flatten)]
    pub dial_fields: DialParams,
}

#[skip_serializing_none]
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct HostsServer {
    pub tag: String,
    pub path: SingleOrMultipleValue<String>,

    pub predefined: Option<HostsServerPredefined>,
}

pub type HostsServerPredefined = IndexMap<String, SingleOrMultipleValue<String>>;

#[skip_serializing_none]
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TcpServer {
    pub tag: String,
    pub server: String,
    pub server_port: Option<u32>,
    #[serde(flatten)]
    pub dial_fields: DialParams,
}

#[skip_serializing_none]
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct UdpServer {
    pub tag: String,
    pub server: String,
    pub server_port: Option<u32>,
    #[serde(flatten)]
    pub dial_fields: DialParams,
}

#[skip_serializing_none]
#[derive(Serialize, Deserialize, Debug, Clone)] 
pub struct TlsServer {
    pub tag: String,
    pub server: String,
    pub server_port: Option<u32>,
    pub tls: Option<tls::Outbound>,
    #[serde(flatten)]
    pub dial_fields: DialParams,
}

#[skip_serializing_none]
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct QuicServer {
    pub tag: String,
    pub server: String,
    pub server_port: Option<u32>,
    pub tls: Option<tls::Outbound>,
    #[serde(flatten)]
    pub dial_fields: DialParams,
}

#[skip_serializing_none]
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct HttpsServer {
    pub tag: String,
    pub server: String,
    pub server_port: Option<u32>,
    pub path: Option<String>,
    pub headers: Option<IndexMap<String, String>>,
    pub tls: Option<tls::Outbound>,
    #[serde(flatten)]
    pub dial_fields: DialParams,
}

#[skip_serializing_none]
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct H3Server {
    pub tag: String,
    pub server: String,
    pub server_port: Option<u32>,
    pub path: Option<String>,
    pub headers: Option<IndexMap<String, String>>,
    pub tls: Option<tls::Outbound>,
    #[serde(flatten)]
    pub dial_fields: DialParams,
}

#[skip_serializing_none]
#[derive(Serialize, Deserialize, Debug, Clone)] 
pub struct DhcpServer {
    pub tag: String,
    pub interface: Option<String>,
    #[serde(flatten)]
    pub dial_fields: DialParams,
}

#[skip_serializing_none]
#[derive(Default, Serialize, Deserialize, Debug, Clone)]
pub struct FakeIPServer {
    pub tag: String,
    pub inet4_range: Option<String>,
    pub inet6_range: Option<String>,
}

#[skip_serializing_none]
#[derive(Default, Serialize, Deserialize, Debug, Clone)]
pub struct TailscaleServer {
    pub tag: String,
    pub endpoint: String,
    pub accept_default_resolvers: Option<bool>,
}

#[skip_serializing_none]
#[derive(Default, Serialize, Deserialize, Debug, Clone)]
pub struct ResolvedServer {
    pub tag: String,
    pub service: String,
    pub accept_default_resolvers: Option<bool>,
}


#[skip_serializing_none]
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(untagged)]
pub enum Rule {
    Logical(LogicalRule),
    Basic(BasicRule),
}

#[skip_serializing_none]
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct BasicRule {
    pub action: Option<RuleAction>,
    pub inbound: Option<SingleOrMultipleValue>,
    pub ip_version: Option<IpVersion>,
    pub query_type: Option<Vec<QueryType>>,
    pub network: Option<Network>,
    pub auth_user: Option<SingleOrMultipleValue>,
    pub protocol: Option<Vec<Protocol>>,
    pub domain: Option<SingleOrMultipleValue>,
    pub domain_suffix: Option<SingleOrMultipleValue>,
    pub domain_keyword: Option<SingleOrMultipleValue>,
    pub domain_regex: Option<SingleOrMultipleValue>,
    pub source_ip_cidr: Option<SingleOrMultipleValue>,
    pub source_ip_is_private: Option<bool>,
    pub ip_cidr: Option<SingleOrMultipleValue>,
    pub ip_is_private: Option<bool>,
    pub ip_accept_any: Option<bool>,
    pub source_port: Option<Vec<u16>>,
    pub source_port_range: Option<SingleOrMultipleValue>,
    pub port: Option<Vec<u16>>,
    pub port_range: Option<SingleOrMultipleValue>,
    pub process_name: Option<SingleOrMultipleValue>,
    pub process_path: Option<SingleOrMultipleValue>,
    pub process_path_regex: Option<SingleOrMultipleValue>,
    pub package_name: Option<SingleOrMultipleValue>,
    pub user: Option<SingleOrMultipleValue>,
    pub user_id: Option<Vec<u32>>,
    pub clash_mode: Option<String>,
    pub network_type: Option<NetworkType>,
    pub network_is_expensive: Option<bool>,
    pub network_is_constrained: Option<bool>,
    pub interface_address: Option<IndexMap<String, SingleOrMultipleValue>>,
    pub network_interface_address: Option<IndexMap<String, SingleOrMultipleValue>>,
    pub default_interface_address: Option<String>,
    pub wifi_ssid: Option<SingleOrMultipleValue>,
    pub wifi_bssid: Option<SingleOrMultipleValue>,
    pub rule_set: Option<SingleOrMultipleValue>,
    pub rule_set_ip_cidr_match_source: Option<bool>,
    pub rule_set_ip_cidr_accept_empty: Option<bool>,
    pub invert: Option<bool>,
    pub server: Option<String>,
    pub strategy: Option<Strategy>,
}

#[skip_serializing_none]
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct LogicalRule {
    pub r#type: String,
    pub mode: LogicalMode,
    pub rules: Vec<BasicRule>,
    pub action: RuleAction,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "snake_case")]
pub enum Protocol {
    Http,
    Tls,
    Quic,
    Stun,
    Dns,
    Bittorrent,
    Dtls,
}



#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RuleAction {
    Route,
    RouteOptions,
    Reject,
    Predefined,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_legacy_server_deserialize() {
        // Eternal Network style: type empty, address + tag + detour
        let json = r#"{"type":"","tag":"remote","address":"1.1.1.1","detour":"proxy"}"#;
        let server: Server = serde_json::from_str(json).unwrap();
        match &server {
            Server::Legacy(l) => {
                assert_eq!(l.tag.as_deref(), Some("remote"));
                assert_eq!(l.address, "1.1.1.1");
                assert_eq!(l.detour.as_deref(), Some("proxy"));
            }
            _ => panic!("expected Legacy variant"),
        }
    }

    #[test]
    fn test_legacy_server_https_address() {
        let json = r#"{"type":"","address":"https://223.5.5.5/dns-query","tag":"local","detour":"direct"}"#;
        let server: Server = serde_json::from_str(json).unwrap();
        match &server {
            Server::Legacy(l) => {
                assert_eq!(l.address, "https://223.5.5.5/dns-query");
                assert_eq!(l.tag.as_deref(), Some("local"));
            }
            _ => panic!("expected Legacy variant"),
        }
    }

    #[test]
    fn test_legacy_server_rcode() {
        let json = r#"{"type":"","address":"rcode://refused","tag":"block"}"#;
        let server: Server = serde_json::from_str(json).unwrap();
        match &server {
            Server::Legacy(l) => {
                assert_eq!(l.address, "rcode://refused");
                assert_eq!(l.tag.as_deref(), Some("block"));
            }
            _ => panic!("expected Legacy variant"),
        }
    }
}

