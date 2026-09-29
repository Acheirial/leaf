use std::collections::HashMap;
use std::path::Path;

use anyhow::Result;
use protobuf::Message;
use serde_derive::{Deserialize, Serialize};

use crate::config::{external_rule, internal};

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct Dns {
    pub servers: Option<Vec<DnsServer>>,
    pub hosts: Option<HashMap<String, Vec<String>>>,
    #[serde(rename = "clientIp", alias = "client_ip")]
    pub client_ip: Option<String>,
    pub tag: Option<String>,
    #[serde(rename = "queryStrategy", alias = "query_strategy")]
    pub query_strategy: Option<String>,
    #[serde(rename = "disableCache", alias = "disable_cache")]
    pub disable_cache: Option<bool>,
    #[serde(rename = "serveStale", alias = "serve_stale")]
    pub serve_stale: Option<bool>,
    #[serde(rename = "serveExpiredTTL", alias = "serve_expired_ttl")]
    pub serve_expired_ttl: Option<u32>,
    #[serde(rename = "disableFallback", alias = "disable_fallback")]
    pub disable_fallback: Option<bool>,
    #[serde(rename = "disableFallbackIfMatch", alias = "disable_fallback_if_match")]
    pub disable_fallback_if_match: Option<bool>,
    #[serde(rename = "enableParallelQuery", alias = "enable_parallel_query")]
    pub enable_parallel_query: Option<bool>,
    #[serde(rename = "useSystemHosts", alias = "use_system_hosts")]
    pub use_system_hosts: Option<bool>,
}

/// A DNS server entry, which may be configured either as a plain address string
/// or as an object with per-server options. Xray writes the plain form.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(untagged)]
pub enum DnsServer {
    Address(String),
    Server(DnsServerObject),
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct DnsServerObject {
    pub address: String,
    pub port: Option<u16>,
    #[serde(rename = "skipFallback", alias = "skip_fallback")]
    pub skip_fallback: Option<bool>,
    pub domains: Option<Vec<String>>,
    #[serde(rename = "expectedIPs", alias = "expectIPs", alias = "expected_ips")]
    pub expected_ips: Option<Vec<String>>,
    #[serde(rename = "unexpectedIPs", alias = "unexpected_ips")]
    pub unexpected_ips: Option<Vec<String>>,
    #[serde(rename = "queryStrategy", alias = "query_strategy")]
    pub query_strategy: Option<String>,
    pub tag: Option<String>,
    #[serde(rename = "timeoutMs", alias = "timeout_ms")]
    pub timeout_ms: Option<u64>,
    #[serde(rename = "disableCache", alias = "disable_cache")]
    pub disable_cache: Option<bool>,
    #[serde(rename = "serveStale", alias = "serve_stale")]
    pub serve_stale: Option<bool>,
    #[serde(rename = "serveExpiredTTL", alias = "serve_expired_ttl")]
    pub serve_expired_ttl: Option<u32>,
    #[serde(rename = "finalQuery", alias = "final_query")]
    pub final_query: Option<bool>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Log {
    pub level: Option<String>,
    pub output: Option<String>,
    pub format: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct CatInboundSettings {
    pub network: Option<String>,
    pub address: String,
    pub port: u16,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(deny_unknown_fields)]
pub struct SocksInboundSettings {
    pub username: Option<String>,
    pub password: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(deny_unknown_fields)]
pub struct WebSocketInboundSettings {
    pub path: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct HcInboundSettings {
    pub path: String,
    #[serde(default)]
    pub request: Option<String>,
    pub response: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(deny_unknown_fields)]
pub struct AMuxInboundSettings {
    pub actors: Option<Vec<String>>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct QuicInboundSettings {
    pub certificate: Option<String>,
    #[serde(rename = "certificateKey", alias = "certificate_key")]
    pub certificate_key: Option<String>,
    #[serde(rename = "rawCertificate", alias = "raw_certificate")]
    pub raw_certificate: Option<Vec<String>>,
    #[serde(rename = "rawCertificateKey", alias = "raw_certificate_key")]
    pub raw_certificate_key: Option<Vec<String>>,
    pub alpn: Option<Vec<String>>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TlsCertificate {
    #[serde(rename = "certificateFile", alias = "certificate_file")]
    pub certificate_file: Option<String>,
    pub certificate: Option<Vec<String>>,
    #[serde(rename = "keyFile", alias = "key_file")]
    pub key_file: Option<String>,
    pub key: Option<Vec<String>>,
    pub usage: Option<String>,
    #[serde(rename = "ocspStapling", alias = "ocsp_stapling")]
    pub ocsp_stapling: Option<u64>,
    #[serde(rename = "oneTimeLoading", alias = "one_time_loading")]
    pub one_time_loading: Option<bool>,
    #[serde(rename = "buildChain", alias = "build_chain")]
    pub build_chain: Option<bool>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TlsInboundSettings {
    pub certificate: Option<String>,
    #[serde(rename = "certificateKey", alias = "certificate_key")]
    pub certificate_key: Option<String>,
    #[serde(rename = "rawCertificate", alias = "raw_certificate")]
    pub raw_certificate: Option<Vec<String>>,
    #[serde(rename = "rawCertificateKey", alias = "raw_certificate_key")]
    pub raw_certificate_key: Option<Vec<String>>,
    #[serde(rename = "echConfig", alias = "ech_config")]
    pub ech_config: Option<String>,
    #[serde(rename = "echKey", alias = "ech_key")]
    pub ech_key: Option<String>,
    pub certificates: Option<Vec<TlsCertificate>>,
    #[serde(rename = "rejectUnknownSni", alias = "reject_unknown_sni")]
    pub reject_unknown_sni: Option<bool>,
    #[serde(rename = "echServerKeys", alias = "ech_server_keys")]
    pub ech_server_keys: Option<String>,
    #[serde(rename = "minVersion", alias = "min_version")]
    pub min_version: Option<String>,
    #[serde(rename = "maxVersion", alias = "max_version")]
    pub max_version: Option<String>,
    #[serde(rename = "cipherSuites", alias = "cipher_suites")]
    pub cipher_suites: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(deny_unknown_fields)]
pub struct ChainInboundSettings {
    pub actors: Option<Vec<String>>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(deny_unknown_fields)]
pub struct MptpInboundSettings {}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TunInboundSettings {
    pub auto: Option<bool>,
    pub fd: Option<i32>,
    pub name: Option<String>,
    pub address: Option<String>,
    pub gateway: Option<String>,
    pub netmask: Option<String>,
    pub mtu: Option<i32>,
    #[serde(rename = "fakeDnsExclude", alias = "fake_dns_exclude")]
    pub fake_dns_exclude: Option<Vec<String>>,
    #[serde(rename = "fakeDnsInclude", alias = "fake_dns_include")]
    pub fake_dns_include: Option<Vec<String>>,
    pub tun2socks: Option<String>,
    pub wintun: Option<String>,
    #[serde(rename = "dnsServers", alias = "dns_servers")]
    pub dns_servers: Option<Vec<String>>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct VlessUser {
    pub id: Option<String>,
    pub flow: Option<String>,
    pub encryption: Option<String>,
    pub level: Option<String>,
}

/// A VLESS user as written in the config: either a bare UUID string or an
/// object with per-user options. Xray accepts both forms in the same list.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(untagged)]
pub enum VlessUserEntry {
    Id(String),
    Object(VlessUser),
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct VlessFallback {
    pub name: Option<String>,
    pub alpn: Option<String>,
    pub path: Option<String>,
    #[serde(rename = "type")]
    pub type_field: Option<String>,
    pub dest: Option<String>,
    pub xver: Option<u32>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct VlessInboundSettings {
    pub users: Option<Vec<VlessUserEntry>>,
    pub decryption: Option<String>,
    pub fallbacks: Option<Vec<VlessFallback>>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct RealityInboundSettings {
    pub dest: Option<String>,
    #[serde(rename = "serverNames", alias = "server_names")]
    pub server_names: Option<Vec<String>>,
    #[serde(rename = "privateKey", alias = "private_key")]
    pub private_key: Option<String>,
    #[serde(rename = "shortIds", alias = "short_ids")]
    pub short_ids: Option<Vec<String>>,
    pub show: Option<bool>,
    pub xver: Option<u32>,
    pub target: Option<Vec<String>>,
    #[serde(rename = "maxTimeDiffMs", alias = "max_time_diff_ms")]
    pub max_time_diff_ms: Option<u32>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct XhttpInboundSettings {
    pub host: Option<String>,
    pub path: Option<String>,
    pub mode: Option<String>,
    pub extra: Option<String>,
    #[serde(rename = "downloadSettings", alias = "download_settings")]
    pub download_settings: Option<String>,
    #[serde(rename = "maxUploadSize", alias = "max_upload_size")]
    pub max_upload_size: Option<u32>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct FinalmaskMask {
    #[serde(rename = "maskType", alias = "mask_type")]
    pub mask_type: Option<String>,
    pub settings: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct FinalmaskInboundSettings {
    pub tcp: Option<Vec<FinalmaskMask>>,
    pub udp: Option<Vec<FinalmaskMask>>,
    #[serde(rename = "tcpTemplate", alias = "tcp_template")]
    pub tcp_template: Option<String>,
    #[serde(rename = "udpTemplate", alias = "udp_template")]
    pub udp_template: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Hysteria2InboundSettings {
    pub password: Option<String>,
    pub obfs: Option<String>,
    #[serde(rename = "obfsPassword", alias = "obfs_password")]
    pub obfs_password: Option<String>,
    pub masquerade: Option<String>,
    #[serde(rename = "masqueradeFile", alias = "masquerade_file")]
    pub masquerade_file: Option<String>,
    #[serde(rename = "masqueradeString", alias = "masquerade_string")]
    pub masquerade_string: Option<String>,
    #[serde(rename = "upMbps", alias = "up_mbps")]
    pub up_mbps: Option<u64>,
    #[serde(rename = "downMbps", alias = "down_mbps")]
    pub down_mbps: Option<u64>,
    #[serde(rename = "ignoreClientBandwidth", alias = "ignore_client_bandwidth")]
    pub ignore_client_bandwidth: Option<bool>,
    pub certificate: Option<String>,
    #[serde(rename = "certificateKey", alias = "certificate_key")]
    pub certificate_key: Option<String>,
    #[serde(rename = "udpIdleTimeout", alias = "udp_idle_timeout")]
    pub udp_idle_timeout: Option<u64>,
    pub mtu: Option<u32>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct RedirectOutboundSettings {
    pub address: Option<String>,
    pub port: Option<u16>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SocksOutboundSettings {
    pub address: Option<String>,
    pub port: Option<u16>,
    pub username: Option<String>,
    pub password: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ShadowsocksOutboundSettings {
    pub address: Option<String>,
    pub port: Option<u16>,
    pub method: Option<String>,
    pub password: Option<String>,
    pub prefix: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ObfsOutboundSettings {
    pub method: Option<String>,
    pub host: Option<String>,
    pub path: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(deny_unknown_fields)]
pub struct TrojanOutboundSettings {
    pub address: Option<String>,
    pub port: Option<u16>,
    pub password: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct VMessOutboundSettings {
    pub address: Option<String>,
    pub port: Option<u16>,
    pub uuid: Option<String>,
    pub security: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct VlessOutboundSettings {
    pub address: Option<String>,
    pub port: Option<u16>,
    pub uuid: Option<String>,
    pub encryption: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct RealityOutboundSettings {
    #[serde(rename = "serverName", alias = "server_name")]
    pub server_name: Option<String>,
    #[serde(rename = "publicKey", alias = "public_key")]
    pub public_key: Option<String>,
    #[serde(rename = "shortId", alias = "short_id")]
    pub short_id: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TryAllOutboundSettings {
    pub actors: Option<Vec<String>>,
    #[serde(rename = "delayBase", alias = "delay_base")]
    pub delay_base: Option<u32>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct StaticOutboundSettings {
    pub actors: Option<Vec<String>>,
    pub method: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TlsOutboundSettings {
    #[serde(rename = "serverName", alias = "server_name")]
    pub server_name: Option<String>,
    pub alpn: Option<Vec<String>>,
    pub certificate: Option<String>,
    #[serde(rename = "certificateKey", alias = "certificate_key")]
    pub certificate_key: Option<String>,
    #[serde(rename = "rawCertificate", alias = "raw_certificate")]
    pub raw_certificate: Option<Vec<String>>,
    #[serde(rename = "rawCertificateKey", alias = "raw_certificate_key")]
    pub raw_certificate_key: Option<Vec<String>>,
    pub insecure: Option<bool>,
    #[serde(rename = "ech")]
    pub ech: Option<bool>,
    #[serde(rename = "echDisableDnsLookup", alias = "ech_disable_dns_lookup")]
    pub ech_disable_dns_lookup: Option<bool>,
    #[serde(rename = "echConfigList", alias = "ech_config_list")]
    pub ech_config_list: Option<String>,
    pub certificates: Option<Vec<TlsCertificate>>,
    #[serde(rename = "pinnedPeerCertSha256", alias = "pinned_peer_cert_sha256")]
    pub pinned_peer_cert_sha256: Option<String>,
    #[serde(rename = "verifyPeerCertByName", alias = "verify_peer_cert_by_name")]
    pub verify_peer_cert_by_name: Option<String>,
    #[serde(rename = "minVersion", alias = "min_version")]
    pub min_version: Option<String>,
    #[serde(rename = "maxVersion", alias = "max_version")]
    pub max_version: Option<String>,
    #[serde(rename = "cipherSuites", alias = "cipher_suites")]
    pub cipher_suites: Option<String>,
    #[serde(rename = "curvePreferences", alias = "curve_preferences")]
    pub curve_preferences: Option<Vec<String>>,
    #[serde(rename = "enableSessionResumption", alias = "enable_session_resumption")]
    pub enable_session_resumption: Option<bool>,
    #[serde(rename = "disableSystemRoot", alias = "disable_system_root")]
    pub disable_system_root: Option<bool>,
    #[serde(rename = "masterKeyLog", alias = "master_key_log")]
    pub master_key_log: Option<String>,
    pub fingerprint: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct WebSocketOutboundSettings {
    pub path: Option<String>,
    pub headers: Option<HashMap<String, String>>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AMuxOutboundSettings {
    pub address: Option<String>,
    pub port: Option<u16>,
    pub actors: Option<Vec<String>>,
    #[serde(rename = "maxAccepts", alias = "max_accepts")]
    pub max_accepts: Option<u32>,
    pub concurrency: Option<u32>,
    pub max_recv_bytes: Option<u64>,
    pub max_lifetime: Option<u64>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct QuicOutboundSettings {
    pub address: Option<String>,
    pub port: Option<u16>,
    #[serde(rename = "serverName", alias = "server_name")]
    pub server_name: Option<String>,
    pub certificate: Option<String>,
    #[serde(rename = "certificateKey", alias = "certificate_key")]
    pub certificate_key: Option<String>,
    #[serde(rename = "rawCertificate", alias = "raw_certificate")]
    pub raw_certificate: Option<Vec<String>>,
    #[serde(rename = "rawCertificateKey", alias = "raw_certificate_key")]
    pub raw_certificate_key: Option<Vec<String>>,
    pub alpn: Option<Vec<String>>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(deny_unknown_fields)]
pub struct ChainOutboundSettings {
    pub actors: Option<Vec<String>>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct MptpOutboundSettings {
    pub actors: Option<Vec<String>>,
    pub address: Option<String>,
    pub port: Option<u16>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct FailOverOutboundSettings {
    pub actors: Option<Vec<String>>,
    #[serde(rename = "failTimeout", alias = "fail_timeout")]
    pub fail_timeout: Option<u32>,
    #[serde(rename = "healthCheck", alias = "health_check")]
    pub health_check: Option<bool>,
    #[serde(rename = "healthCheckTimeout", alias = "health_check_timeout")]
    pub health_check_timeout: Option<u32>,
    #[serde(rename = "healthCheckDelay", alias = "health_check_delay")]
    pub health_check_delay: Option<u32>,
    #[serde(rename = "healthCheckActive", alias = "health_check_active")]
    pub health_check_active: Option<u32>,
    #[serde(rename = "healthCheckPrefers", alias = "health_check_prefers")]
    pub health_check_prefers: Option<Vec<String>>,
    #[serde(rename = "checkInterval", alias = "check_interval")]
    pub check_interval: Option<u32>,
    #[serde(rename = "healthCheckOnStart", alias = "health_check_on_start")]
    pub health_check_on_start: Option<bool>,
    #[serde(rename = "healthCheckWait", alias = "health_check_wait")]
    pub health_check_wait: Option<bool>,
    #[serde(rename = "healthCheckAttempts", alias = "health_check_attempts")]
    pub health_check_attempts: Option<u32>,
    #[serde(
        rename = "healthCheckSuccessPercentage",
        alias = "health_check_success_percentage"
    )]
    pub health_check_success_percentage: Option<u32>,
    pub failover: Option<bool>,
    #[serde(rename = "fallbackCache", alias = "fallback_cache")]
    pub fallback_cache: Option<bool>,
    #[serde(rename = "cacheSize", alias = "cache_size")]
    pub cache_size: Option<u32>,
    #[serde(rename = "cacheTimeout", alias = "cache_timeout")]
    pub cache_timeout: Option<u32>,
    #[serde(rename = "lastResort", alias = "last_resort")]
    pub last_resort: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SelectOutboundSettings {
    pub actors: Option<Vec<String>>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PluginOutboundSettings {
    pub path: Option<String>,
    pub args: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct XhttpOutboundSettings {
    pub host: Option<String>,
    pub path: Option<String>,
    pub mode: Option<String>,
    pub extra: Option<String>,
    #[serde(rename = "maxUploadSize", alias = "max_upload_size")]
    pub max_upload_size: Option<u32>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct FinalmaskOutboundSettings {
    pub tcp: Option<Vec<FinalmaskMask>>,
    pub udp: Option<Vec<FinalmaskMask>>,
    #[serde(rename = "tcpTemplate", alias = "tcp_template")]
    pub tcp_template: Option<String>,
    #[serde(rename = "udpTemplate", alias = "udp_template")]
    pub udp_template: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Hysteria2OutboundSettings {
    pub server: Option<String>,
    pub password: Option<String>,
    pub obfs: Option<String>,
    #[serde(rename = "obfsPassword", alias = "obfs_password")]
    pub obfs_password: Option<String>,
    pub sni: Option<String>,
    pub insecure: Option<bool>,
    pub alpn: Option<String>,
    #[serde(rename = "upMbps", alias = "up_mbps")]
    pub up_mbps: Option<u64>,
    #[serde(rename = "downMbps", alias = "down_mbps")]
    pub down_mbps: Option<u64>,
    #[serde(rename = "udpIdleTimeout", alias = "udp_idle_timeout")]
    pub udp_idle_timeout: Option<u64>,
    pub mtu: Option<u32>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Inbound {
    pub tag: Option<String>,
    pub address: Option<String>,
    pub port: Option<u16>,
    #[serde(flatten)]
    pub settings: InboundSettings,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(tag = "protocol", rename_all = "lowercase")]
pub enum InboundSettings {
    Cat {
        #[serde(default)]
        settings: Option<CatInboundSettings>,
    },
    #[serde(rename = "websocket", alias = "ws")]
    WebSocket {
        #[serde(default)]
        settings: Option<WebSocketInboundSettings>,
    },
    Hc {
        #[serde(default)]
        settings: Option<HcInboundSettings>,
    },
    AMux {
        #[serde(default)]
        settings: Option<AMuxInboundSettings>,
    },
    Quic {
        #[serde(default)]
        settings: Option<QuicInboundSettings>,
    },
    Tls {
        #[serde(default)]
        settings: Option<TlsInboundSettings>,
    },
    Chain {
        #[serde(default)]
        settings: Option<ChainInboundSettings>,
    },
    Mptp {
        #[serde(default)]
        settings: Option<MptpInboundSettings>,
    },
    Tun {
        #[serde(default)]
        settings: Option<TunInboundSettings>,
    },
    Socks {
        #[serde(default)]
        settings: Option<SocksInboundSettings>,
    },
    Vless {
        #[serde(default)]
        settings: Option<VlessInboundSettings>,
    },
    Reality {
        #[serde(default)]
        settings: Option<RealityInboundSettings>,
    },
    Xhttp {
        #[serde(default)]
        settings: Option<XhttpInboundSettings>,
    },
    Finalmask {
        #[serde(default)]
        settings: Option<FinalmaskInboundSettings>,
    },
    Hysteria2 {
        #[serde(default)]
        settings: Option<Hysteria2InboundSettings>,
    },
    Http,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Outbound {
    pub tag: Option<String>,
    #[serde(flatten)]
    pub settings: OutboundSettings,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(tag = "protocol", rename_all = "lowercase")]
pub enum OutboundSettings {
    Redirect {
        #[serde(default)]
        settings: Option<RedirectOutboundSettings>,
    },
    Socks {
        #[serde(default)]
        settings: Option<SocksOutboundSettings>,
    },
    Shadowsocks {
        #[serde(default)]
        settings: Option<ShadowsocksOutboundSettings>,
    },
    Obfs {
        #[serde(default)]
        settings: Option<ObfsOutboundSettings>,
    },
    Trojan {
        #[serde(default)]
        settings: Option<TrojanOutboundSettings>,
    },
    VMess {
        #[serde(default)]
        settings: Option<VMessOutboundSettings>,
    },
    Vless {
        #[serde(default)]
        settings: Option<VlessOutboundSettings>,
    },
    Reality {
        #[serde(default)]
        settings: Option<RealityOutboundSettings>,
    },
    TryAll {
        #[serde(default)]
        settings: Option<TryAllOutboundSettings>,
    },
    Static {
        #[serde(default)]
        settings: Option<StaticOutboundSettings>,
    },
    Tls {
        #[serde(default)]
        settings: Option<TlsOutboundSettings>,
    },
    #[serde(rename = "websocket", alias = "ws")]
    WebSocket {
        #[serde(default)]
        settings: Option<WebSocketOutboundSettings>,
    },
    AMux {
        #[serde(default)]
        settings: Option<AMuxOutboundSettings>,
    },
    Quic {
        #[serde(default)]
        settings: Option<QuicOutboundSettings>,
    },
    Chain {
        #[serde(default)]
        settings: Option<ChainOutboundSettings>,
    },
    Mptp {
        #[serde(default)]
        settings: Option<MptpOutboundSettings>,
    },
    FailOver {
        #[serde(default)]
        settings: Option<FailOverOutboundSettings>,
    },
    Select {
        #[serde(default)]
        settings: Option<SelectOutboundSettings>,
    },
    Plugin {
        #[serde(default)]
        settings: Option<PluginOutboundSettings>,
    },
    Xhttp {
        #[serde(default)]
        settings: Option<XhttpOutboundSettings>,
    },
    Finalmask {
        #[serde(default)]
        settings: Option<FinalmaskOutboundSettings>,
    },
    Hysteria2 {
        #[serde(default)]
        settings: Option<Hysteria2OutboundSettings>,
    },
    Direct,
    Drop,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Rule {
    #[serde(rename = "type")]
    pub type_field: Option<String>,
    pub ip: Option<Vec<String>>,
    pub domain: Option<Vec<String>>,
    #[serde(rename = "domainKeyword", alias = "domain_keyword")]
    pub domain_keyword: Option<Vec<String>>,
    #[serde(rename = "domainSuffix", alias = "domain_suffix")]
    pub domain_suffix: Option<Vec<String>>,
    pub geoip: Option<Vec<String>>,
    pub external: Option<Vec<String>>,
    #[serde(rename = "portRange", alias = "port_range")]
    pub port_range: Option<Vec<String>>,
    pub network: Option<Vec<String>>,
    #[serde(rename = "inboundTag", alias = "inbound_tag")]
    pub inbound_tag: Option<Vec<String>>,
    #[serde(rename = "processName", alias = "process_name")]
    pub process_name: Option<Vec<String>>,
    pub target: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Router {
    pub rules: Option<Vec<Rule>>,
    #[serde(rename = "domainResolve", alias = "domain_resolve")]
    pub domain_resolve: Option<bool>,
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct Config {
    pub log: Option<Log>,
    pub env: Option<HashMap<String, String>>,
    pub inbounds: Option<Vec<Inbound>>,
    pub outbounds: Option<Vec<Outbound>>,
    pub router: Option<Router>,
    pub dns: Option<Dns>,
}

fn is_inline_certificate(certificate: &str) -> bool {
    certificate.contains("-----BEGIN")
}

/// Resolves a certificate or a private key, either of which may be given
/// inline or as a path.
///
/// The two halves of a keypair are configured the same way and have to be read
/// the same way. They were not: a certificate was recognised inline and a key
/// never was, so an inline key became a path under the asset directory made of
/// PEM, and what the operator saw was "no private keys found" about a key that
/// was right there in the configuration.
fn resolve_certificate(value: &str) -> String {
    if is_inline_certificate(value) {
        return value.to_string();
    }
    let path = Path::new(value);
    if path.is_absolute() {
        return path.to_string_lossy().to_string();
    }
    Path::new(&*crate::option::ASSET_LOCATION)
        .join(path)
        .to_string_lossy()
        .to_string()
}

fn validate_non_empty_str(value: &str, field_name: &str, protocol: &str) -> Result<()> {
    if value.trim().is_empty() {
        return Err(anyhow::anyhow!(
            "invalid [{}] settings: {} cannot be empty",
            protocol,
            field_name
        ));
    }
    Ok(())
}

/// Converts a configured DNS server entry into its internal form, whether it
/// was given as a bare address string or as an object with options.
fn dns_server_to_internal(ext: &DnsServer) -> internal::DnsServer {
    let mut server = internal::DnsServer::new();
    match ext {
        DnsServer::Address(address) => {
            server.address = address.clone();
        }
        DnsServer::Server(object) => {
            server.address = object.address.clone();
            if let Some(port) = object.port {
                server.port = Some(port as u32);
            }
            if let Some(skip_fallback) = object.skip_fallback {
                server.skip_fallback = Some(skip_fallback);
            }
            if let Some(domains) = &object.domains {
                server.domains = domains.clone();
            }
            if let Some(expected_ips) = &object.expected_ips {
                server.expected_ips = expected_ips.clone();
            }
            if let Some(unexpected_ips) = &object.unexpected_ips {
                server.unexpected_ips = unexpected_ips.clone();
            }
            if let Some(query_strategy) = &object.query_strategy {
                server.query_strategy = Some(query_strategy.clone());
            }
            if let Some(tag) = &object.tag {
                server.tag = Some(tag.clone());
            }
            if let Some(timeout_ms) = object.timeout_ms {
                server.timeout_ms = Some(timeout_ms);
            }
            if let Some(disable_cache) = object.disable_cache {
                server.disable_cache = Some(disable_cache);
            }
            if let Some(serve_stale) = object.serve_stale {
                server.serve_stale = Some(serve_stale);
            }
            if let Some(serve_expired_ttl) = object.serve_expired_ttl {
                server.serve_expired_ttl = Some(serve_expired_ttl);
            }
            if let Some(final_query) = object.final_query {
                server.final_query = Some(final_query);
            }
        }
    }
    server
}

/// Converts a configured TLS certificate into its internal form, resolving the
/// file forms the same way the flat certificate fields are resolved.
fn tls_certificate_to_internal(ext: &TlsCertificate) -> internal::TlsCertificate {
    let mut certificate = internal::TlsCertificate::new();
    if let Some(certificate_file) = &ext.certificate_file {
        certificate.certificate_file = Some(resolve_certificate(certificate_file));
    }
    if let Some(inline) = &ext.certificate {
        certificate.certificate = inline.clone();
    }
    if let Some(key_file) = &ext.key_file {
        certificate.key_file = Some(resolve_certificate(key_file));
    }
    if let Some(key) = &ext.key {
        certificate.key = key.clone();
    }
    if let Some(usage) = &ext.usage {
        certificate.usage = Some(usage.clone());
    }
    if let Some(ocsp_stapling) = ext.ocsp_stapling {
        certificate.ocsp_stapling = Some(ocsp_stapling);
    }
    if let Some(one_time_loading) = ext.one_time_loading {
        certificate.one_time_loading = Some(one_time_loading);
    }
    if let Some(build_chain) = ext.build_chain {
        certificate.build_chain = Some(build_chain);
    }
    certificate
}

/// Converts a configured finalmask mask entry into its internal form. The
/// per-mask `settings` blob is raw JSON that the implementation parses, so it
/// is written through unchanged.
fn finalmask_mask_to_internal(ext: &FinalmaskMask) -> internal::FinalmaskMask {
    let mut mask = internal::FinalmaskMask::new();
    if let Some(mask_type) = &ext.mask_type {
        mask.mask_type = Some(mask_type.clone());
    }
    if let Some(settings) = &ext.settings {
        mask.settings = Some(settings.clone());
    }
    mask
}

pub fn to_internal(mut config: Config) -> Result<internal::Config> {
    let mut log = internal::Log::new();
    if let Some(ext_log) = &config.log {
        if let Some(ext_level) = &ext_log.level {
            match ext_level.to_lowercase().as_str() {
                "trace" => log.level = protobuf::EnumOrUnknown::new(internal::log::Level::TRACE),
                "debug" => log.level = protobuf::EnumOrUnknown::new(internal::log::Level::DEBUG),
                "info" => log.level = protobuf::EnumOrUnknown::new(internal::log::Level::INFO),
                "warn" => log.level = protobuf::EnumOrUnknown::new(internal::log::Level::WARN),
                "error" => log.level = protobuf::EnumOrUnknown::new(internal::log::Level::ERROR),
                "none" => log.level = protobuf::EnumOrUnknown::new(internal::log::Level::NONE),
                _ => {
                    tracing::warn!("unknown log level `{}`, falling back to WARN", ext_level);
                    log.level = protobuf::EnumOrUnknown::new(internal::log::Level::WARN)
                }
            }
        }

        if let Some(ext_output) = &ext_log.output {
            match ext_output.as_str() {
                "console" => {
                    log.output = protobuf::EnumOrUnknown::new(internal::log::Output::CONSOLE)
                }
                _ => {
                    log.output = protobuf::EnumOrUnknown::new(internal::log::Output::FILE);
                    log.output_file = ext_output.clone();
                }
            }
        }

        if let Some(ext_format) = &ext_log.format {
            match ext_format.to_lowercase().as_str() {
                "compact" => {
                    log.format = protobuf::EnumOrUnknown::new(internal::log::Format::COMPACT)
                }
                _ => log.format = protobuf::EnumOrUnknown::new(internal::log::Format::FULL),
            }
        }
    }

    let mut inbounds = Vec::new();
    if let Some(ext_inbounds) = &config.inbounds {
        for ext_inbound in ext_inbounds {
            let mut inbound = internal::Inbound::new();
            if let Some(ext_tag) = &ext_inbound.tag {
                inbound.tag = ext_tag.clone();
            }
            if let Some(ext_address) = &ext_inbound.address {
                inbound.address = ext_address.to_owned();
            } else {
                inbound.address = "127.0.0.1".to_string();
            }
            if let Some(ext_port) = ext_inbound.port {
                inbound.port = ext_port as u32;
            }

            match &ext_inbound.settings {
                #[cfg(any(
                    target_os = "ios",
                    target_os = "android",
                    target_os = "macos",
                    target_os = "linux",
                    target_os = "windows"
                ))]
                InboundSettings::Tun {
                    settings: ext_settings,
                } => {
                    inbound.protocol = "tun".to_string();
                    if let Some(ext_settings) = ext_settings {
                        let mut settings = internal::TunInboundSettings::new();
                        let mut fake_dns_exclude = Vec::new();
                        if let Some(ext_excludes) = &ext_settings.fake_dns_exclude {
                            for ext_exclude in ext_excludes {
                                fake_dns_exclude.push(ext_exclude.clone());
                            }
                        }
                        if !fake_dns_exclude.is_empty() {
                            settings.fake_dns_exclude = fake_dns_exclude;
                        }

                        let mut fake_dns_include = Vec::new();
                        if let Some(ext_includes) = &ext_settings.fake_dns_include {
                            for ext_include in ext_includes {
                                fake_dns_include.push(ext_include.clone());
                            }
                        }
                        if !fake_dns_include.is_empty() {
                            settings.fake_dns_include = fake_dns_include;
                        }

                        let fd = ext_settings.fd.unwrap_or(-1);
                        if fd >= 0 {
                            settings.fd = fd;
                            let mut ignored = Vec::new();
                            if ext_settings.name.is_some() {
                                ignored.push("name");
                            }
                            if ext_settings.address.is_some() {
                                ignored.push("address");
                            }
                            if ext_settings.gateway.is_some() {
                                ignored.push("gateway");
                            }
                            if ext_settings.netmask.is_some() {
                                ignored.push("netmask");
                            }
                            if ext_settings.mtu.is_some() {
                                ignored.push("mtu");
                            }
                            if !ignored.is_empty() {
                                tracing::warn!(
                                    "tun inbound: option(s) {} are ignored because `fd` is set",
                                    ignored.join(", ")
                                );
                            }
                        } else {
                            settings.fd = -1; // disable fd option
                            if let Some(ext_name) = &ext_settings.name {
                                settings.name = ext_name.clone();
                            }
                            if let Some(ext_address) = &ext_settings.address {
                                settings.address = ext_address.clone();
                            }
                            if let Some(ext_gateway) = &ext_settings.gateway {
                                settings.gateway = ext_gateway.clone();
                            }
                            if let Some(ext_netmask) = &ext_settings.netmask {
                                settings.netmask = ext_netmask.clone();
                            }
                            if let Some(ext_auto) = ext_settings.auto {
                                settings.auto = ext_auto;
                            }
                            if let Some(ext_mtu) = ext_settings.mtu {
                                settings.mtu = ext_mtu;
                            } else {
                                settings.mtu = 1500;
                            }
                        }
                        if let Some(ext_tun2socks) = &ext_settings.tun2socks {
                            settings.tun2socks = ext_tun2socks.clone();
                        }
                        if let Some(ext_wintun) = &ext_settings.wintun {
                            settings.wintun = Some(ext_wintun.clone());
                        }
                        if let Some(ext_dns_servers) = &ext_settings.dns_servers {
                            for ext_dns_server in ext_dns_servers {
                                settings.dns_servers.push(ext_dns_server.clone());
                            }
                        }
                        let settings = settings
                            .write_to_bytes()
                            .map_err(|e| anyhow::anyhow!("failed to serialize settings: {}", e))?;
                        inbound.settings = settings;
                    }
                    inbounds.push(inbound);
                }
                #[cfg(not(any(
                    target_os = "ios",
                    target_os = "android",
                    target_os = "macos",
                    target_os = "linux",
                    target_os = "windows"
                )))]
                InboundSettings::Tun { .. } => {
                    return Err(anyhow::anyhow!(
                        "tun inbound is not supported on this platform"
                    ));
                }
                InboundSettings::Cat {
                    settings: ext_settings,
                } => {
                    inbound.protocol = "cat".to_string();
                    if let Some(ext_settings) = ext_settings {
                        let mut settings = internal::CatInboundSettings::new();
                        settings.network =
                            ext_settings.network.clone().unwrap_or("tcp".to_string());
                        settings.address = ext_settings.address.clone();
                        settings.port = ext_settings.port as u32;
                        let settings = settings
                            .write_to_bytes()
                            .map_err(|e| anyhow::anyhow!("failed to serialize settings: {}", e))?;
                        inbound.settings = settings;
                    }
                    inbounds.push(inbound);
                }
                InboundSettings::Hc {
                    settings: ext_settings,
                } => {
                    inbound.protocol = "hc".to_string();
                    if let Some(ext_settings) = ext_settings {
                        let mut settings = internal::HcInboundSettings::new();
                        settings.path = ext_settings.path.clone();
                        settings.request = ext_settings.request.clone().unwrap_or_default();
                        settings.response = ext_settings.response.clone();
                        let settings = settings
                            .write_to_bytes()
                            .map_err(|e| anyhow::anyhow!("failed to serialize settings: {}", e))?;
                        inbound.settings = settings;
                    }
                    inbounds.push(inbound);
                }
                InboundSettings::Socks {
                    settings: ext_settings,
                } => {
                    inbound.protocol = "socks".to_string();
                    if let Some(ext_settings) = ext_settings {
                        let mut settings = internal::SocksInboundSettings::new();
                        if let Some(ext_username) = &ext_settings.username {
                            settings.username = ext_username.clone();
                        }
                        if let Some(ext_password) = &ext_settings.password {
                            settings.password = ext_password.clone();
                        }
                        let settings = settings
                            .write_to_bytes()
                            .map_err(|e| anyhow::anyhow!("failed to serialize settings: {}", e))?;
                        inbound.settings = settings;
                    }
                    inbounds.push(inbound);
                }
                InboundSettings::Vless {
                    settings: ext_settings,
                } => {
                    inbound.protocol = "vless".to_string();
                    if let Some(ext_settings) = ext_settings {
                        let mut settings = internal::VlessInboundSettings::new();
                        if let Some(ext_users) = &ext_settings.users {
                            for ext_user in ext_users {
                                match ext_user {
                                    VlessUserEntry::Id(id) => settings.users.push(id.clone()),
                                    VlessUserEntry::Object(user) => {
                                        let mut int_user = internal::VlessUser::new();
                                        if let Some(id) = &user.id {
                                            int_user.id = Some(id.clone());
                                        }
                                        if let Some(flow) = &user.flow {
                                            int_user.flow = Some(flow.clone());
                                        }
                                        if let Some(encryption) = &user.encryption {
                                            int_user.encryption = Some(encryption.clone());
                                        }
                                        if let Some(level) = &user.level {
                                            int_user.level = Some(level.clone());
                                        }
                                        settings.user_objects.push(int_user);
                                    }
                                }
                            }
                        }
                        if let Some(ext_decryption) = &ext_settings.decryption {
                            settings.decryption = Some(ext_decryption.clone());
                        }
                        if let Some(ext_fallbacks) = &ext_settings.fallbacks {
                            for ext_fallback in ext_fallbacks {
                                let mut fallback = internal::VlessFallback::new();
                                if let Some(name) = &ext_fallback.name {
                                    fallback.name = Some(name.clone());
                                }
                                if let Some(alpn) = &ext_fallback.alpn {
                                    fallback.alpn = Some(alpn.clone());
                                }
                                if let Some(path) = &ext_fallback.path {
                                    fallback.path = Some(path.clone());
                                }
                                if let Some(type_field) = &ext_fallback.type_field {
                                    fallback.type_ = Some(type_field.clone());
                                }
                                if let Some(dest) = &ext_fallback.dest {
                                    fallback.dest = Some(dest.clone());
                                }
                                if let Some(xver) = ext_fallback.xver {
                                    fallback.xver = Some(xver);
                                }
                                settings.fallbacks.push(fallback);
                            }
                        }
                        let settings = settings
                            .write_to_bytes()
                            .map_err(|e| anyhow::anyhow!("failed to serialize settings: {}", e))?;
                        inbound.settings = settings;
                    }
                    inbounds.push(inbound);
                }
                InboundSettings::Reality {
                    settings: ext_settings,
                } => {
                    inbound.protocol = "reality".to_string();
                    if let Some(ext_settings) = ext_settings {
                        let mut settings = internal::RealityInboundSettings::new();
                        if let Some(dest) = &ext_settings.dest {
                            settings.dest = Some(dest.clone());
                        }
                        if let Some(server_names) = &ext_settings.server_names {
                            settings.server_names.extend_from_slice(server_names);
                        }
                        if let Some(private_key) = &ext_settings.private_key {
                            settings.private_key = Some(private_key.clone());
                        }
                        if let Some(short_ids) = &ext_settings.short_ids {
                            settings.short_ids.extend_from_slice(short_ids);
                        }
                        if let Some(show) = ext_settings.show {
                            settings.show = Some(show);
                        }
                        if let Some(xver) = ext_settings.xver {
                            settings.xver = Some(xver);
                        }
                        if let Some(target) = &ext_settings.target {
                            settings.target.extend_from_slice(target);
                        }
                        if let Some(max_time_diff_ms) = ext_settings.max_time_diff_ms {
                            settings.max_time_diff_ms = Some(max_time_diff_ms);
                        }
                        let settings = settings
                            .write_to_bytes()
                            .map_err(|e| anyhow::anyhow!("failed to serialize settings: {}", e))?;
                        inbound.settings = settings;
                    }
                    inbounds.push(inbound);
                }
                InboundSettings::Xhttp {
                    settings: ext_settings,
                } => {
                    inbound.protocol = "xhttp".to_string();
                    if let Some(ext_settings) = ext_settings {
                        let mut settings = internal::XhttpInboundSettings::new();
                        if let Some(host) = &ext_settings.host {
                            settings.host = Some(host.clone());
                        }
                        if let Some(path) = &ext_settings.path {
                            settings.path = Some(path.clone());
                        }
                        if let Some(mode) = &ext_settings.mode {
                            settings.mode = Some(mode.clone());
                        }
                        if let Some(extra) = &ext_settings.extra {
                            settings.extra = Some(extra.clone());
                        }
                        if let Some(download_settings) = &ext_settings.download_settings {
                            settings.download_settings = Some(download_settings.clone());
                        }
                        if let Some(max_upload_size) = ext_settings.max_upload_size {
                            settings.max_upload_size = Some(max_upload_size);
                        }
                        let settings = settings
                            .write_to_bytes()
                            .map_err(|e| anyhow::anyhow!("failed to serialize settings: {}", e))?;
                        inbound.settings = settings;
                    }
                    inbounds.push(inbound);
                }
                InboundSettings::Finalmask {
                    settings: ext_settings,
                } => {
                    inbound.protocol = "finalmask".to_string();
                    if let Some(ext_settings) = ext_settings {
                        let mut settings = internal::FinalmaskInboundSettings::new();
                        if let Some(tcp) = &ext_settings.tcp {
                            for mask in tcp {
                                settings.tcp.push(finalmask_mask_to_internal(mask));
                            }
                        }
                        if let Some(udp) = &ext_settings.udp {
                            for mask in udp {
                                settings.udp.push(finalmask_mask_to_internal(mask));
                            }
                        }
                        if let Some(tcp_template) = &ext_settings.tcp_template {
                            settings.tcp_template = Some(tcp_template.clone());
                        }
                        if let Some(udp_template) = &ext_settings.udp_template {
                            settings.udp_template = Some(udp_template.clone());
                        }
                        let settings = settings
                            .write_to_bytes()
                            .map_err(|e| anyhow::anyhow!("failed to serialize settings: {}", e))?;
                        inbound.settings = settings;
                    }
                    inbounds.push(inbound);
                }
                InboundSettings::Hysteria2 {
                    settings: ext_settings,
                } => {
                    inbound.protocol = "hysteria2".to_string();
                    if let Some(ext_settings) = ext_settings {
                        let mut settings = internal::Hysteria2InboundSettings::new();
                        if let Some(password) = &ext_settings.password {
                            settings.password = Some(password.clone());
                        }
                        if let Some(obfs) = &ext_settings.obfs {
                            settings.obfs = Some(obfs.clone());
                        }
                        if let Some(obfs_password) = &ext_settings.obfs_password {
                            settings.obfs_password = Some(obfs_password.clone());
                        }
                        if let Some(masquerade) = &ext_settings.masquerade {
                            settings.masquerade = Some(masquerade.clone());
                        }
                        if let Some(masquerade_file) = &ext_settings.masquerade_file {
                            settings.masquerade_file = Some(masquerade_file.clone());
                        }
                        if let Some(masquerade_string) = &ext_settings.masquerade_string {
                            settings.masquerade_string = Some(masquerade_string.clone());
                        }
                        if let Some(up_mbps) = ext_settings.up_mbps {
                            settings.up_mbps = Some(up_mbps);
                        }
                        if let Some(down_mbps) = ext_settings.down_mbps {
                            settings.down_mbps = Some(down_mbps);
                        }
                        if let Some(ignore_client_bandwidth) = ext_settings.ignore_client_bandwidth {
                            settings.ignore_client_bandwidth = Some(ignore_client_bandwidth);
                        }
                        if let Some(certificate) = &ext_settings.certificate {
                            settings.certificate = Some(certificate.clone());
                        }
                        if let Some(certificate_key) = &ext_settings.certificate_key {
                            settings.certificate_key = Some(certificate_key.clone());
                        }
                        if let Some(udp_idle_timeout) = ext_settings.udp_idle_timeout {
                            settings.udp_idle_timeout = Some(udp_idle_timeout);
                        }
                        if let Some(mtu) = ext_settings.mtu {
                            settings.mtu = Some(mtu);
                        }
                        let settings = settings
                            .write_to_bytes()
                            .map_err(|e| anyhow::anyhow!("failed to serialize settings: {}", e))?;
                        inbound.settings = settings;
                    }
                    inbounds.push(inbound);
                }
                InboundSettings::Http => {
                    inbound.protocol = "http".to_string();
                    inbounds.push(inbound);
                }
                InboundSettings::WebSocket {
                    settings: ext_settings,
                } => {
                    inbound.protocol = "ws".to_string();
                    if let Some(ext_settings) = ext_settings {
                        let mut settings = internal::WebSocketInboundSettings::new();
                        match &ext_settings.path {
                            Some(ext_path) if !ext_path.is_empty() => {
                                settings.path = ext_path.clone();
                            }
                            _ => {
                                settings.path = "/".to_string();
                            }
                        };
                        let settings = settings
                            .write_to_bytes()
                            .map_err(|e| anyhow::anyhow!("failed to serialize settings: {}", e))?;
                        inbound.settings = settings;
                    }
                    inbounds.push(inbound);
                }
                InboundSettings::AMux {
                    settings: ext_settings,
                } => {
                    inbound.protocol = "amux".to_string();
                    if let Some(ext_settings) = ext_settings {
                        let mut settings = internal::AMuxInboundSettings::new();
                        if let Some(ext_actors) = &ext_settings.actors {
                            for ext_actor in ext_actors {
                                settings.actors.push(ext_actor.clone());
                            }
                        }
                        let settings = settings
                            .write_to_bytes()
                            .map_err(|e| anyhow::anyhow!("failed to serialize settings: {}", e))?;
                        inbound.settings = settings;
                    }
                    inbounds.push(inbound);
                }
                InboundSettings::Quic {
                    settings: ext_settings,
                } => {
                    inbound.protocol = "quic".to_string();
                    if let Some(ext_settings) = ext_settings {
                        let mut settings = internal::QuicInboundSettings::new();
                        if let Some(ext_raw_certificate) = &ext_settings.raw_certificate {
                            settings.certificate = ext_raw_certificate.join("\n");
                        } else if let Some(ext_certificate) = &ext_settings.certificate {
                            settings.certificate = resolve_certificate(ext_certificate);
                        }
                        if let Some(ext_raw_certificate_key) = &ext_settings.raw_certificate_key {
                            settings.certificate_key = ext_raw_certificate_key.join("\n");
                        } else if let Some(ext_certificate_key) = &ext_settings.certificate_key {
                            settings.certificate_key = resolve_certificate(ext_certificate_key);
                        }
                        if let Some(ext_alpns) = &ext_settings.alpn {
                            for ext_alpn in ext_alpns {
                                settings.alpn.push(ext_alpn.clone());
                            }
                        }
                        let settings = settings
                            .write_to_bytes()
                            .map_err(|e| anyhow::anyhow!("failed to serialize settings: {}", e))?;
                        inbound.settings = settings;
                    }
                    inbounds.push(inbound);
                }
                InboundSettings::Tls {
                    settings: ext_settings,
                } => {
                    inbound.protocol = "tls".to_string();
                    if let Some(ext_settings) = ext_settings {
                        if ext_settings.ech_config.is_some() || ext_settings.ech_key.is_some() {
                            match (&ext_settings.ech_config, &ext_settings.ech_key) {
                                (Some(ech_config), Some(ech_key)) => {
                                    validate_non_empty_str(ech_config, "echConfig", "tls inbound")?;
                                    validate_non_empty_str(ech_key, "echKey", "tls inbound")?;
                                    return Err(anyhow::anyhow!(
                                        "invalid [tls inbound] settings: inbound ECH is not supported yet; remove echConfig and echKey"
                                    ));
                                }
                                _ => {
                                    return Err(anyhow::anyhow!(
                                        "invalid [tls inbound] settings: echConfig and echKey must be set together"
                                    ))
                                }
                            }
                        }
                        let mut settings = internal::TlsInboundSettings::new();
                        if let Some(ext_raw_certificate) = &ext_settings.raw_certificate {
                            settings.certificate = ext_raw_certificate.join("\n");
                        } else if let Some(ext_certificate) = &ext_settings.certificate {
                            settings.certificate = resolve_certificate(ext_certificate);
                        }
                        if let Some(ext_raw_certificate_key) = &ext_settings.raw_certificate_key {
                            settings.certificate_key = ext_raw_certificate_key.join("\n");
                        } else if let Some(ext_certificate_key) = &ext_settings.certificate_key {
                            settings.certificate_key = resolve_certificate(ext_certificate_key);
                        }
                        if let Some(ext_ech_config) = &ext_settings.ech_config {
                            settings.ech_config = ext_ech_config.clone();
                        }
                        if let Some(ext_ech_key) = &ext_settings.ech_key {
                            settings.ech_key = ext_ech_key.clone();
                        }
                        if let Some(ext_certificates) = &ext_settings.certificates {
                            for ext_certificate in ext_certificates {
                                settings
                                    .certificates
                                    .push(tls_certificate_to_internal(ext_certificate));
                            }
                        }
                        if let Some(ext_reject_unknown_sni) = ext_settings.reject_unknown_sni {
                            settings.reject_unknown_sni = Some(ext_reject_unknown_sni);
                        }
                        if let Some(ext_ech_server_keys) = &ext_settings.ech_server_keys {
                            settings.ech_server_keys = Some(ext_ech_server_keys.clone());
                        }
                        if let Some(ext_min_version) = &ext_settings.min_version {
                            settings.min_version = Some(ext_min_version.clone());
                        }
                        if let Some(ext_max_version) = &ext_settings.max_version {
                            settings.max_version = Some(ext_max_version.clone());
                        }
                        if let Some(ext_cipher_suites) = &ext_settings.cipher_suites {
                            settings.cipher_suites = Some(ext_cipher_suites.clone());
                        }
                        let settings = settings
                            .write_to_bytes()
                            .map_err(|e| anyhow::anyhow!("failed to serialize settings: {}", e))?;
                        inbound.settings = settings;
                    }
                    inbounds.push(inbound);
                }
                InboundSettings::Chain {
                    settings: ext_settings,
                } => {
                    inbound.protocol = "chain".to_string();
                    if let Some(ext_settings) = ext_settings {
                        let mut settings = internal::ChainInboundSettings::new();
                        if let Some(ext_actors) = &ext_settings.actors {
                            for ext_actor in ext_actors {
                                settings.actors.push(ext_actor.clone());
                            }
                        }
                        let settings = settings
                            .write_to_bytes()
                            .map_err(|e| anyhow::anyhow!("failed to serialize settings: {}", e))?;
                        inbound.settings = settings;
                    }
                    inbounds.push(inbound);
                }
                InboundSettings::Mptp {
                    settings: ext_settings,
                } => {
                    inbound.protocol = "mptp".to_string();
                    if let Some(_ext_settings) = ext_settings {
                        let settings = internal::MptpInboundSettings::new();
                        let settings = settings
                            .write_to_bytes()
                            .map_err(|e| anyhow::anyhow!("failed to serialize settings: {}", e))?;
                        inbound.settings = settings;
                    }
                    inbounds.push(inbound);
                }
            }
        }
    }

    let mut outbounds = Vec::new();
    if let Some(ext_outbounds) = &config.outbounds {
        for ext_outbound in ext_outbounds {
            let mut outbound = internal::Outbound::new();
            if let Some(ext_tag) = &ext_outbound.tag {
                outbound.tag = ext_tag.clone();
            }
            match &ext_outbound.settings {
                OutboundSettings::Direct => {
                    outbound.protocol = "direct".to_string();
                    outbounds.push(outbound);
                }
                OutboundSettings::Drop => {
                    outbound.protocol = "drop".to_string();
                    outbounds.push(outbound);
                }
                OutboundSettings::Redirect {
                    settings: ext_settings,
                } => {
                    outbound.protocol = "redirect".to_string();
                    if let Some(ext_settings) = ext_settings {
                        let mut settings = internal::RedirectOutboundSettings::new();
                        if let Some(ext_address) = &ext_settings.address {
                            settings.address = ext_address.clone();
                        }
                        if let Some(ext_port) = ext_settings.port {
                            settings.port = ext_port as u32;
                        }
                        let settings = settings
                            .write_to_bytes()
                            .map_err(|e| anyhow::anyhow!("failed to serialize settings: {}", e))?;
                        outbound.settings = settings;
                    }
                    outbounds.push(outbound);
                }
                OutboundSettings::Socks {
                    settings: ext_settings,
                } => {
                    outbound.protocol = "socks".to_string();
                    if let Some(ext_settings) = ext_settings {
                        let mut settings = internal::SocksOutboundSettings::new();
                        if let Some(ext_address) = &ext_settings.address {
                            settings.address = ext_address.clone();
                        }
                        if let Some(ext_port) = ext_settings.port {
                            settings.port = ext_port as u32;
                        }
                        if let Some(ext_username) = &ext_settings.username {
                            settings.username = ext_username.clone();
                        }
                        if let Some(ext_password) = &ext_settings.password {
                            settings.password = ext_password.clone();
                        }
                        let settings = settings
                            .write_to_bytes()
                            .map_err(|e| anyhow::anyhow!("failed to serialize settings: {}", e))?;
                        outbound.settings = settings;
                    }
                    outbounds.push(outbound);
                }
                OutboundSettings::Shadowsocks {
                    settings: ext_settings,
                } => {
                    outbound.protocol = "shadowsocks".to_string();
                    if let Some(ext_settings) = ext_settings {
                        let mut settings = internal::ShadowsocksOutboundSettings::new();
                        if let Some(ext_address) = &ext_settings.address {
                            settings.address = ext_address.clone();
                        }
                        if let Some(ext_port) = ext_settings.port {
                            settings.port = ext_port as u32;
                        }
                        if let Some(ext_method) = &ext_settings.method {
                            settings.method = ext_method.clone();
                        } else {
                            settings.method = "chacha20-ietf-poly1305".to_string();
                        }
                        if let Some(ext_password) = &ext_settings.password {
                            settings.password = ext_password.clone();
                        }
                        if let Some(ext_prefix) = &ext_settings.prefix {
                            settings.prefix = Some(ext_prefix.clone());
                        }
                        let settings = settings
                            .write_to_bytes()
                            .map_err(|e| anyhow::anyhow!("failed to serialize settings: {}", e))?;
                        outbound.settings = settings;
                    }
                    outbounds.push(outbound);
                }
                OutboundSettings::Obfs {
                    settings: ext_settings,
                } => {
                    outbound.protocol = "obfs".to_string();
                    if let Some(ext_settings) = ext_settings {
                        let mut settings = internal::ObfsOutboundSettings::new();
                        if let Some(ext_method) = &ext_settings.method {
                            settings.method = ext_method.clone();
                        }
                        if let Some(ext_host) = &ext_settings.host {
                            settings.host = ext_host.clone();
                        }
                        if let Some(ext_path) = &ext_settings.path {
                            settings.path = ext_path.clone();
                        }
                        let settings = settings
                            .write_to_bytes()
                            .map_err(|e| anyhow::anyhow!("failed to serialize settings: {}", e))?;
                        outbound.settings = settings;
                    }
                    outbounds.push(outbound);
                }
                OutboundSettings::Trojan {
                    settings: ext_settings,
                } => {
                    outbound.protocol = "trojan".to_string();
                    if let Some(ext_settings) = ext_settings {
                        let mut settings = internal::TrojanOutboundSettings::new();
                        if let Some(ext_address) = &ext_settings.address {
                            settings.address = ext_address.clone();
                        }
                        if let Some(ext_port) = ext_settings.port {
                            settings.port = ext_port as u32;
                        }
                        if let Some(ext_password) = &ext_settings.password {
                            settings.password = ext_password.clone();
                        }
                        let settings = settings
                            .write_to_bytes()
                            .map_err(|e| anyhow::anyhow!("failed to serialize settings: {}", e))?;
                        outbound.settings = settings;
                    }
                    outbounds.push(outbound);
                }
                OutboundSettings::VMess {
                    settings: ext_settings,
                } => {
                    outbound.protocol = "vmess".to_string();
                    if let Some(ext_settings) = ext_settings {
                        let mut settings = internal::VMessOutboundSettings::new();
                        if let Some(ext_address) = &ext_settings.address {
                            settings.address = ext_address.clone();
                        }
                        if let Some(ext_port) = ext_settings.port {
                            settings.port = ext_port as u32;
                        }
                        if let Some(ext_uuid) = &ext_settings.uuid {
                            settings.uuid = ext_uuid.clone();
                        }
                        settings.security = ext_settings
                            .security
                            .clone()
                            .unwrap_or_else(|| "chacha20-ietf-poly1305".to_string());
                        let settings = settings
                            .write_to_bytes()
                            .map_err(|e| anyhow::anyhow!("failed to serialize settings: {}", e))?;
                        outbound.settings = settings;
                    }
                    outbounds.push(outbound);
                }
                OutboundSettings::Vless {
                    settings: ext_settings,
                } => {
                    outbound.protocol = "vless".to_string();
                    if let Some(ext_settings) = ext_settings {
                        let mut settings = internal::VlessOutboundSettings::new();
                        if let Some(ext_address) = &ext_settings.address {
                            settings.address = ext_address.clone();
                        }
                        if let Some(ext_port) = ext_settings.port {
                            settings.port = ext_port as u32;
                        }
                        if let Some(ext_uuid) = &ext_settings.uuid {
                            settings.uuid = ext_uuid.clone();
                        }
                        if let Some(ext_encryption) = &ext_settings.encryption {
                            settings.encryption = Some(ext_encryption.clone());
                        }
                        let settings = settings
                            .write_to_bytes()
                            .map_err(|e| anyhow::anyhow!("failed to serialize settings: {}", e))?;
                        outbound.settings = settings;
                    }
                    outbounds.push(outbound);
                }
                OutboundSettings::Reality {
                    settings: ext_settings,
                } => {
                    outbound.protocol = "reality".to_string();
                    if let Some(ext_settings) = ext_settings {
                        let mut settings = internal::RealityOutboundSettings::new();
                        if let Some(ext_server_name) = &ext_settings.server_name {
                            settings.server_name = ext_server_name.clone();
                        }
                        if let Some(ext_public_key) = &ext_settings.public_key {
                            settings.public_key = ext_public_key.clone();
                        }
                        if let Some(ext_short_id) = &ext_settings.short_id {
                            settings.short_id = ext_short_id.clone();
                        }
                        let settings = settings
                            .write_to_bytes()
                            .map_err(|e| anyhow::anyhow!("failed to serialize settings: {}", e))?;
                        outbound.settings = settings;
                    }
                    outbounds.push(outbound);
                }
                OutboundSettings::Xhttp {
                    settings: ext_settings,
                } => {
                    outbound.protocol = "xhttp".to_string();
                    if let Some(ext_settings) = ext_settings {
                        let mut settings = internal::XhttpOutboundSettings::new();
                        if let Some(host) = &ext_settings.host {
                            settings.host = Some(host.clone());
                        }
                        if let Some(path) = &ext_settings.path {
                            settings.path = Some(path.clone());
                        }
                        if let Some(mode) = &ext_settings.mode {
                            settings.mode = Some(mode.clone());
                        }
                        if let Some(extra) = &ext_settings.extra {
                            settings.extra = Some(extra.clone());
                        }
                        if let Some(max_upload_size) = ext_settings.max_upload_size {
                            settings.max_upload_size = Some(max_upload_size);
                        }
                        let settings = settings
                            .write_to_bytes()
                            .map_err(|e| anyhow::anyhow!("failed to serialize settings: {}", e))?;
                        outbound.settings = settings;
                    }
                    outbounds.push(outbound);
                }
                OutboundSettings::Finalmask {
                    settings: ext_settings,
                } => {
                    outbound.protocol = "finalmask".to_string();
                    if let Some(ext_settings) = ext_settings {
                        let mut settings = internal::FinalmaskOutboundSettings::new();
                        if let Some(tcp) = &ext_settings.tcp {
                            for mask in tcp {
                                settings.tcp.push(finalmask_mask_to_internal(mask));
                            }
                        }
                        if let Some(udp) = &ext_settings.udp {
                            for mask in udp {
                                settings.udp.push(finalmask_mask_to_internal(mask));
                            }
                        }
                        if let Some(tcp_template) = &ext_settings.tcp_template {
                            settings.tcp_template = Some(tcp_template.clone());
                        }
                        if let Some(udp_template) = &ext_settings.udp_template {
                            settings.udp_template = Some(udp_template.clone());
                        }
                        let settings = settings
                            .write_to_bytes()
                            .map_err(|e| anyhow::anyhow!("failed to serialize settings: {}", e))?;
                        outbound.settings = settings;
                    }
                    outbounds.push(outbound);
                }
                OutboundSettings::Hysteria2 {
                    settings: ext_settings,
                } => {
                    outbound.protocol = "hysteria2".to_string();
                    if let Some(ext_settings) = ext_settings {
                        let mut settings = internal::Hysteria2OutboundSettings::new();
                        if let Some(server) = &ext_settings.server {
                            settings.server = Some(server.clone());
                        }
                        if let Some(password) = &ext_settings.password {
                            settings.password = Some(password.clone());
                        }
                        if let Some(obfs) = &ext_settings.obfs {
                            settings.obfs = Some(obfs.clone());
                        }
                        if let Some(obfs_password) = &ext_settings.obfs_password {
                            settings.obfs_password = Some(obfs_password.clone());
                        }
                        if let Some(sni) = &ext_settings.sni {
                            settings.sni = Some(sni.clone());
                        }
                        if let Some(insecure) = ext_settings.insecure {
                            settings.insecure = Some(insecure);
                        }
                        if let Some(alpn) = &ext_settings.alpn {
                            settings.alpn = Some(alpn.clone());
                        }
                        if let Some(up_mbps) = ext_settings.up_mbps {
                            settings.up_mbps = Some(up_mbps);
                        }
                        if let Some(down_mbps) = ext_settings.down_mbps {
                            settings.down_mbps = Some(down_mbps);
                        }
                        if let Some(udp_idle_timeout) = ext_settings.udp_idle_timeout {
                            settings.udp_idle_timeout = Some(udp_idle_timeout);
                        }
                        if let Some(mtu) = ext_settings.mtu {
                            settings.mtu = Some(mtu);
                        }
                        let settings = settings
                            .write_to_bytes()
                            .map_err(|e| anyhow::anyhow!("failed to serialize settings: {}", e))?;
                        outbound.settings = settings;
                    }
                    outbounds.push(outbound);
                }
                OutboundSettings::Tls {
                    settings: ext_settings,
                } => {
                    outbound.protocol = "tls".to_string();
                    if let Some(ext_settings) = ext_settings {
                        if let Some(ext_ech_config_list) = &ext_settings.ech_config_list {
                            validate_non_empty_str(
                                ext_ech_config_list,
                                "echConfigList",
                                "tls outbound",
                            )?;
                        }
                        let mut settings = internal::TlsOutboundSettings::new();
                        if let Some(ext_server_name) = &ext_settings.server_name {
                            settings.server_name = ext_server_name.clone();
                        }
                        if let Some(ext_alpn) = &ext_settings.alpn {
                            settings.alpn = ext_alpn.clone();
                        }
                        if let Some(ext_raw_certificate) = &ext_settings.raw_certificate {
                            settings.certificate = ext_raw_certificate.join("\n");
                        } else if let Some(ext_certificate) = &ext_settings.certificate {
                            settings.certificate = resolve_certificate(ext_certificate);
                        }
                        if let Some(ext_raw_certificate_key) = &ext_settings.raw_certificate_key {
                            settings.certificate_key = ext_raw_certificate_key.join("\n");
                        } else if let Some(ext_certificate_key) = &ext_settings.certificate_key {
                            settings.certificate_key = resolve_certificate(ext_certificate_key);
                        }
                        if let Some(ext_insecure) = ext_settings.insecure {
                            settings.insecure = ext_insecure;
                        }
                        if let Some(ext_ech) = ext_settings.ech {
                            settings.ech = ext_ech;
                        }
                        if let Some(ext_ech_disable_dns_lookup) =
                            ext_settings.ech_disable_dns_lookup
                        {
                            settings.ech_disable_dns_lookup = ext_ech_disable_dns_lookup;
                        }
                        if let Some(ext_ech_config_list) = &ext_settings.ech_config_list {
                            settings.ech_config_list = ext_ech_config_list.clone();
                        }
                        if let Some(ext_certificates) = &ext_settings.certificates {
                            for ext_certificate in ext_certificates {
                                settings
                                    .certificates
                                    .push(tls_certificate_to_internal(ext_certificate));
                            }
                        }
                        if let Some(ext_pinned_peer_cert_sha256) =
                            &ext_settings.pinned_peer_cert_sha256
                        {
                            settings.pinned_peer_cert_sha256 =
                                Some(ext_pinned_peer_cert_sha256.clone());
                        }
                        if let Some(ext_verify_peer_cert_by_name) =
                            &ext_settings.verify_peer_cert_by_name
                        {
                            settings.verify_peer_cert_by_name =
                                Some(ext_verify_peer_cert_by_name.clone());
                        }
                        if let Some(ext_min_version) = &ext_settings.min_version {
                            settings.min_version = Some(ext_min_version.clone());
                        }
                        if let Some(ext_max_version) = &ext_settings.max_version {
                            settings.max_version = Some(ext_max_version.clone());
                        }
                        if let Some(ext_cipher_suites) = &ext_settings.cipher_suites {
                            settings.cipher_suites = Some(ext_cipher_suites.clone());
                        }
                        if let Some(ext_curve_preferences) = &ext_settings.curve_preferences {
                            settings.curve_preferences = ext_curve_preferences.clone();
                        }
                        if let Some(ext_enable_session_resumption) =
                            ext_settings.enable_session_resumption
                        {
                            settings.enable_session_resumption =
                                Some(ext_enable_session_resumption);
                        }
                        if let Some(ext_disable_system_root) = ext_settings.disable_system_root {
                            settings.disable_system_root = Some(ext_disable_system_root);
                        }
                        if let Some(ext_master_key_log) = &ext_settings.master_key_log {
                            settings.master_key_log = Some(ext_master_key_log.clone());
                        }
                        if let Some(ext_fingerprint) = &ext_settings.fingerprint {
                            settings.fingerprint = Some(ext_fingerprint.clone());
                        }
                        let settings = settings
                            .write_to_bytes()
                            .map_err(|e| anyhow::anyhow!("failed to serialize settings: {}", e))?;
                        outbound.settings = settings;
                    }
                    outbounds.push(outbound);
                }
                OutboundSettings::WebSocket {
                    settings: ext_settings,
                } => {
                    outbound.protocol = "ws".to_string();
                    if let Some(ext_settings) = ext_settings {
                        let mut settings = internal::WebSocketOutboundSettings::new();
                        if let Some(ext_path) = &ext_settings.path {
                            settings.path = ext_path.clone();
                        }
                        if let Some(ext_headers) = &ext_settings.headers {
                            settings.headers = ext_headers.clone();
                        }
                        let settings = settings
                            .write_to_bytes()
                            .map_err(|e| anyhow::anyhow!("failed to serialize settings: {}", e))?;
                        outbound.settings = settings;
                    }
                    outbounds.push(outbound);
                }
                OutboundSettings::TryAll {
                    settings: ext_settings,
                } => {
                    outbound.protocol = "tryall".to_string();
                    if let Some(ext_settings) = ext_settings {
                        let mut settings = internal::TryAllOutboundSettings::new();
                        if let Some(ext_actors) = &ext_settings.actors {
                            for ext_actor in ext_actors {
                                settings.actors.push(ext_actor.clone());
                            }
                        }
                        if let Some(ext_delay_base) = ext_settings.delay_base {
                            settings.delay_base = ext_delay_base;
                        } else {
                            settings.delay_base = 0;
                        }
                        let settings = settings
                            .write_to_bytes()
                            .map_err(|e| anyhow::anyhow!("failed to serialize settings: {}", e))?;
                        outbound.settings = settings;
                    }
                    outbounds.push(outbound);
                }
                OutboundSettings::Static {
                    settings: ext_settings,
                } => {
                    outbound.protocol = "static".to_string();
                    if let Some(ext_settings) = ext_settings {
                        let mut settings = internal::StaticOutboundSettings::new();
                        if let Some(ext_actors) = &ext_settings.actors {
                            for ext_actor in ext_actors {
                                settings.actors.push(ext_actor.clone());
                            }
                        }
                        if let Some(ext_method) = &ext_settings.method {
                            settings.method = ext_method.clone();
                        } else {
                            settings.method = "random".to_string();
                        }
                        let settings = settings
                            .write_to_bytes()
                            .map_err(|e| anyhow::anyhow!("failed to serialize settings: {}", e))?;
                        outbound.settings = settings;
                    }
                    outbounds.push(outbound);
                }
                OutboundSettings::FailOver {
                    settings: ext_settings,
                } => {
                    outbound.protocol = "failover".to_string();
                    if let Some(ext_settings) = ext_settings {
                        let mut settings = internal::FailOverOutboundSettings::new();
                        if let Some(ext_actors) = &ext_settings.actors {
                            settings.actors.extend_from_slice(ext_actors);
                        }
                        settings.fail_timeout = ext_settings.fail_timeout.unwrap_or(4); // 4 secs
                        settings.health_check = ext_settings.health_check.unwrap_or(true);
                        settings.health_check_timeout =
                            ext_settings.health_check_timeout.unwrap_or(6); // 6 secs
                        settings.health_check_delay =
                            ext_settings.health_check_delay.unwrap_or(200); // 200ms
                        settings.health_check_active =
                            ext_settings.health_check_active.unwrap_or(15 * 60); // 15 mins
                        if let Some(ext_health_check_prefers) = &ext_settings.health_check_prefers {
                            settings
                                .health_check_prefers
                                .extend_from_slice(ext_health_check_prefers);
                        }
                        settings.health_check_on_start =
                            ext_settings.health_check_on_start.unwrap_or(false);
                        settings.health_check_wait =
                            ext_settings.health_check_wait.unwrap_or(false);
                        settings.health_check_attempts =
                            ext_settings.health_check_attempts.unwrap_or(1);
                        settings.health_check_success_percentage =
                            ext_settings.health_check_success_percentage.unwrap_or(50);
                        settings.check_interval = ext_settings.check_interval.unwrap_or(300); // 300 secs
                        settings.failover = ext_settings.failover.unwrap_or(true);
                        settings.fallback_cache = ext_settings.fallback_cache.unwrap_or(false);
                        settings.cache_size = ext_settings.cache_size.unwrap_or(256);
                        settings.cache_timeout = ext_settings.cache_timeout.unwrap_or(60); // 60 mins
                        settings.last_resort = ext_settings.last_resort.clone();
                        let settings = settings
                            .write_to_bytes()
                            .map_err(|e| anyhow::anyhow!("failed to serialize settings: {}", e))?;
                        outbound.settings = settings;
                    }
                    outbounds.push(outbound);
                }
                OutboundSettings::AMux {
                    settings: ext_settings,
                } => {
                    outbound.protocol = "amux".to_string();
                    if let Some(ext_settings) = ext_settings {
                        let mut settings = internal::AMuxOutboundSettings::new();
                        if let Some(ext_address) = &ext_settings.address {
                            settings.address = ext_address.clone();
                        }
                        if let Some(ext_port) = ext_settings.port {
                            settings.port = ext_port as u32;
                        }
                        if let Some(ext_actors) = &ext_settings.actors {
                            for ext_actor in ext_actors {
                                settings.actors.push(ext_actor.clone());
                            }
                        }
                        settings.max_accepts = ext_settings.max_accepts.unwrap_or(8);
                        settings.concurrency = ext_settings.concurrency.unwrap_or(2);
                        settings.max_recv_bytes = ext_settings.max_recv_bytes.unwrap_or_default();
                        settings.max_lifetime = ext_settings.max_lifetime.unwrap_or_default();
                        let settings = settings
                            .write_to_bytes()
                            .map_err(|e| anyhow::anyhow!("failed to serialize settings: {}", e))?;
                        outbound.settings = settings;
                    }
                    outbounds.push(outbound);
                }
                OutboundSettings::Quic {
                    settings: ext_settings,
                } => {
                    outbound.protocol = "quic".to_string();
                    if let Some(ext_settings) = ext_settings {
                        let mut settings = internal::QuicOutboundSettings::new();
                        if let Some(ext_address) = &ext_settings.address {
                            settings.address = ext_address.clone();
                        }
                        if let Some(ext_port) = ext_settings.port {
                            settings.port = ext_port as u32;
                        }
                        if let Some(ext_server_name) = &ext_settings.server_name {
                            settings.server_name = ext_server_name.clone();
                        }
                        if let Some(ext_raw_certificate) = &ext_settings.raw_certificate {
                            settings.certificate = ext_raw_certificate.join("\n");
                        } else if let Some(ext_certificate) = &ext_settings.certificate {
                            settings.certificate = resolve_certificate(ext_certificate);
                        }
                        if let Some(ext_raw_certificate_key) = &ext_settings.raw_certificate_key {
                            settings.certificate_key = ext_raw_certificate_key.join("\n");
                        } else if let Some(ext_certificate_key) = &ext_settings.certificate_key {
                            settings.certificate_key = resolve_certificate(ext_certificate_key);
                        }
                        if let Some(ext_alpns) = &ext_settings.alpn {
                            settings.alpn = ext_alpns.clone();
                        }
                        let settings = settings
                            .write_to_bytes()
                            .map_err(|e| anyhow::anyhow!("failed to serialize settings: {}", e))?;
                        outbound.settings = settings;
                    }
                    outbounds.push(outbound);
                }
                OutboundSettings::Chain {
                    settings: ext_settings,
                } => {
                    outbound.protocol = "chain".to_string();
                    if let Some(ext_settings) = ext_settings {
                        let mut settings = internal::ChainOutboundSettings::new();
                        if let Some(ext_actors) = &ext_settings.actors {
                            for ext_actor in ext_actors {
                                settings.actors.push(ext_actor.clone());
                            }
                        }
                        let settings = settings
                            .write_to_bytes()
                            .map_err(|e| anyhow::anyhow!("failed to serialize settings: {}", e))?;
                        outbound.settings = settings;
                    }
                    outbounds.push(outbound);
                }
                OutboundSettings::Mptp {
                    settings: ext_settings,
                } => {
                    outbound.protocol = "mptp".to_string();
                    if let Some(ext_settings) = ext_settings {
                        let mut settings = internal::MptpOutboundSettings::new();
                        if let Some(ext_actors) = &ext_settings.actors {
                            for ext_actor in ext_actors {
                                settings.actors.push(ext_actor.clone());
                            }
                        }
                        if let Some(ext_address) = &ext_settings.address {
                            settings.address = ext_address.clone();
                        }
                        if let Some(ext_port) = ext_settings.port {
                            settings.port = ext_port as u32;
                        }
                        let settings = settings
                            .write_to_bytes()
                            .map_err(|e| anyhow::anyhow!("failed to serialize settings: {}", e))?;
                        outbound.settings = settings;
                    }
                    outbounds.push(outbound);
                }
                OutboundSettings::Select {
                    settings: ext_settings,
                } => {
                    outbound.protocol = "select".to_string();
                    if let Some(ext_settings) = ext_settings {
                        let mut settings = internal::SelectOutboundSettings::new();
                        if let Some(ext_actors) = &ext_settings.actors {
                            for ext_actor in ext_actors {
                                settings.actors.push(ext_actor.clone());
                            }
                        }
                        let settings = settings
                            .write_to_bytes()
                            .map_err(|e| anyhow::anyhow!("failed to serialize settings: {}", e))?;
                        outbound.settings = settings;
                    }
                    outbounds.push(outbound);
                }
                OutboundSettings::Plugin {
                    settings: ext_settings,
                } => {
                    outbound.protocol = "plugin".to_string();
                    if let Some(ext_settings) = ext_settings {
                        let mut settings = internal::PluginOutboundSettings::new();
                        if let Some(ext_path) = &ext_settings.path {
                            settings.path = ext_path.clone();
                        }
                        if let Some(ext_args) = &ext_settings.args {
                            settings.args = ext_args.clone();
                        }
                        let settings = settings
                            .write_to_bytes()
                            .map_err(|e| anyhow::anyhow!("failed to serialize settings: {}", e))?;
                        outbound.settings = settings;
                    }
                    outbounds.push(outbound);
                }
            }
        }
    }

    let mut router = protobuf::MessageField::none();
    if let Some(ext_router) = config.router.as_mut() {
        let mut int_router = internal::Router::new();
        let mut rules = Vec::new();
        if let Some(ext_rules) = ext_router.rules.as_mut() {
            for ext_rule in ext_rules.iter_mut() {
                let mut rule = internal::router::Rule::new();
                let target_tag = std::mem::take(&mut ext_rule.target);
                rule.target_tag = target_tag;

                // handle FINAL rule first
                if let Some(type_field) = &ext_rule.type_field {
                    if type_field == "FINAL" {
                        // reorder outbounds to make the FINAL one first
                        let mut idx = None;
                        for (i, v) in outbounds.iter().enumerate() {
                            if v.tag == rule.target_tag {
                                idx = Some(i);
                            }
                        }
                        if let Some(idx) = idx {
                            let final_ob = outbounds.remove(idx);
                            outbounds.insert(0, final_ob);
                        }
                        continue;
                    }
                }

                if let Some(ext_ips) = ext_rule.ip.as_mut() {
                    for ext_ip in ext_ips.drain(0..) {
                        rule.ip_cidrs.push(ext_ip);
                    }
                }
                if let Some(ext_domains) = ext_rule.domain.as_mut() {
                    for ext_domain in ext_domains.drain(0..) {
                        let mut domain = internal::router::rule::Domain::new();
                        domain.type_ = protobuf::EnumOrUnknown::new(
                            internal::router::rule::domain::Type::FULL,
                        );
                        domain.value = ext_domain;
                        rule.domains.push(domain);
                    }
                }
                if let Some(ext_domain_keywords) = ext_rule.domain_keyword.as_mut() {
                    for ext_domain_keyword in ext_domain_keywords.drain(0..) {
                        let mut domain = internal::router::rule::Domain::new();
                        domain.type_ = protobuf::EnumOrUnknown::new(
                            internal::router::rule::domain::Type::PLAIN,
                        );
                        domain.value = ext_domain_keyword;
                        rule.domains.push(domain);
                    }
                }
                if let Some(ext_domain_suffixes) = ext_rule.domain_suffix.as_mut() {
                    for ext_domain_suffix in ext_domain_suffixes.drain(0..) {
                        let mut domain = internal::router::rule::Domain::new();
                        domain.type_ = protobuf::EnumOrUnknown::new(
                            internal::router::rule::domain::Type::DOMAIN,
                        );
                        domain.value = ext_domain_suffix;
                        rule.domains.push(domain);
                    }
                }
                if let Some(ext_geoips) = ext_rule.geoip.as_mut() {
                    for ext_geoip in ext_geoips.drain(0..) {
                        let mut mmdb = internal::router::rule::Mmdb::new();
                        let asset_loc = Path::new(&*crate::option::ASSET_LOCATION);
                        mmdb.file = asset_loc.join("geo.mmdb").to_string_lossy().to_string();
                        mmdb.country_code = ext_geoip;
                        rule.mmdbs.push(mmdb)
                    }
                }
                if let Some(ext_externals) = ext_rule.external.as_mut() {
                    for ext_external in ext_externals.drain(0..) {
                        match external_rule::add_external_rule(&mut rule, &ext_external) {
                            Ok(_) => (),
                            Err(e) => {
                                tracing::warn!("load external rule failed: {}", e);
                            }
                        }
                    }
                }
                if let Some(ext_port_ranges) = ext_rule.port_range.as_mut() {
                    for ext_port_range in ext_port_ranges.drain(0..) {
                        rule.port_ranges.push(ext_port_range);
                    }
                }
                if let Some(ext_networks) = ext_rule.network.as_mut() {
                    for ext_network in ext_networks.drain(0..) {
                        rule.networks.push(ext_network);
                    }
                }
                if let Some(ext_its) = ext_rule.inbound_tag.as_mut() {
                    for it in ext_its.drain(0..) {
                        rule.inbound_tags.push(it);
                    }
                }
                #[cfg(feature = "rule-process-name")]
                if let Some(ext_process_names) = ext_rule.process_name.as_mut() {
                    for process_name in ext_process_names.drain(0..) {
                        rule.process_names.push(process_name);
                    }
                }
                #[cfg(not(feature = "rule-process-name"))]
                if let Some(ext_process_names) = ext_rule.process_name.as_ref() {
                    if !ext_process_names.is_empty() {
                        tracing::warn!(
                            "router rule `process_name` is ignored: build without the `rule-process-name` feature"
                        );
                    }
                }
                rules.push(rule);
            }
        }
        int_router.rules = rules;
        if let Some(ext_domain_resolve) = ext_router.domain_resolve {
            int_router.domain_resolve = ext_domain_resolve;
        }
        router = protobuf::MessageField::some(int_router);
    }

    let mut dns = internal::Dns::new();
    let mut servers: Vec<internal::DnsServer> = Vec::new();
    let mut hosts = HashMap::new();
    if let Some(ext_dns) = &config.dns {
        if let Some(ext_servers) = ext_dns.servers.as_ref() {
            for ext_server in ext_servers {
                servers.push(dns_server_to_internal(ext_server));
            }
        }
        if let Some(ext_hosts) = ext_dns.hosts.as_ref() {
            for (name, static_ips) in ext_hosts.iter() {
                let mut ips = internal::dns::Ips::new();
                let mut ip_vals = Vec::new();
                for ip in static_ips {
                    ip_vals.push(ip.to_owned());
                }
                ips.values = ip_vals;
                hosts.insert(name.to_owned(), ips);
            }
        }
        if let Some(client_ip) = &ext_dns.client_ip {
            dns.client_ip = Some(client_ip.clone());
        }
        if let Some(tag) = &ext_dns.tag {
            dns.tag = Some(tag.clone());
        }
        if let Some(query_strategy) = &ext_dns.query_strategy {
            dns.query_strategy = Some(query_strategy.clone());
        }
        if let Some(disable_cache) = ext_dns.disable_cache {
            dns.disable_cache = Some(disable_cache);
        }
        if let Some(serve_stale) = ext_dns.serve_stale {
            dns.serve_stale = Some(serve_stale);
        }
        if let Some(serve_expired_ttl) = ext_dns.serve_expired_ttl {
            dns.serve_expired_ttl = Some(serve_expired_ttl);
        }
        if let Some(disable_fallback) = ext_dns.disable_fallback {
            dns.disable_fallback = Some(disable_fallback);
        }
        if let Some(disable_fallback_if_match) = ext_dns.disable_fallback_if_match {
            dns.disable_fallback_if_match = Some(disable_fallback_if_match);
        }
        if let Some(enable_parallel_query) = ext_dns.enable_parallel_query {
            dns.enable_parallel_query = Some(enable_parallel_query);
        }
        if let Some(use_system_hosts) = ext_dns.use_system_hosts {
            dns.use_system_hosts = Some(use_system_hosts);
        }
    }
    if servers.is_empty() {
        let mut default_server = internal::DnsServer::new();
        default_server.address = "1.1.1.1".to_string();
        servers.push(default_server);
    }
    dns.servers = servers;
    if !hosts.is_empty() {
        dns.hosts = hosts;
    }

    let mut config = internal::Config::new();
    config.log = protobuf::MessageField::some(log);
    config.inbounds = inbounds;
    config.outbounds = outbounds;
    config.router = router;
    config.dns = protobuf::MessageField::some(dns);
    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::*;

    const INLINE_KEY: &str = "-----BEGIN PRIVATE KEY-----\nMIGH\n-----END PRIVATE KEY-----\n";

    /// Both halves of a keypair are configured the same way and have to be
    /// read the same way. The key was not: it was always taken for a path, so
    /// an inline one became a filename made of PEM under the asset directory,
    /// and what the operator saw was "no private keys found" about a key that
    /// was right there in the configuration.
    #[test]
    fn an_inline_key_is_not_mistaken_for_a_path() {
        assert_eq!(resolve_certificate(INLINE_KEY), INLINE_KEY);
    }

    /// What counts as absolute is the platform's business, and the test has to
    /// ask the same question the code does. A leading slash is a whole path on
    /// Unix; on Windows it names the root of whichever drive is current, so
    /// `resolve_certificate` resolves it against the asset directory like any
    /// other relative path -- correctly, and to something no assertion written
    /// for Unix would recognise.
    #[test]
    fn an_absolute_path_is_left_alone() {
        let absolute = if cfg!(windows) {
            r"C:\leaf\cert.pem"
        } else {
            "/etc/leaf/cert.pem"
        };
        assert_eq!(resolve_certificate(absolute), absolute);
    }

    /// A relative path is still resolved against the asset directory, which is
    /// what makes `"certificate": "cert.pem"` work in a config file.
    #[test]
    fn a_relative_path_is_resolved_against_the_asset_directory() {
        let resolved = resolve_certificate("cert.pem");
        assert!(
            resolved.ends_with("cert.pem") && resolved != "cert.pem",
            "expected a path under the asset directory, got {}",
            resolved
        );
    }
}
