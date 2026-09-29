use std::path::Path;

use anyhow::{anyhow, Result};

use crate::config::{common, internal};

pub use crate::config::common::{
    AMuxInboundSettings, AMuxOutboundSettings, CatInboundSettings, ChainInboundSettings,
    ChainOutboundSettings, Config, Dns, FailOverOutboundSettings, HcInboundSettings, Inbound,
    InboundSettings, Log, ObfsOutboundSettings, Outbound, OutboundSettings, PluginOutboundSettings,
    QuicInboundSettings, QuicOutboundSettings, RealityOutboundSettings, RedirectOutboundSettings,
    Rule, SelectOutboundSettings, ShadowsocksOutboundSettings, SocksOutboundSettings,
    StaticOutboundSettings, TlsInboundSettings, TlsOutboundSettings, TrojanOutboundSettings,
    TryAllOutboundSettings, TunInboundSettings, VMessOutboundSettings, VlessOutboundSettings,
    WebSocketInboundSettings, WebSocketOutboundSettings,
};

pub fn to_internal(config: Config) -> Result<internal::Config> {
    common::to_internal(config)
}

fn apply_env(config: &common::Config) {
    if let Some(env) = &config.env {
        for (k, v) in env {
            if !k.trim().is_empty() {
                std::env::set_var(k, v);
            }
        }
    }
}

/// Top-level keys that mark a YAML document as a leaf configuration.
///
/// YAML is a permissive superset of many other formats: any text that is not
/// obvious YAML can still parse as a scalar or a sequence. A clash-style `.conf`
/// body, for instance, parses as YAML without being a leaf config. Requiring the
/// document to be a mapping that carries at least one of these keys keeps the
/// YAML parser from silently swallowing `.conf` text (see `crate::config::from_string`).
const RECOGNISED_TOP_LEVEL_KEYS: &[&str] =
    &["inbounds", "outbounds", "dns", "log", "router", "api"];

fn is_leaf_config_mapping(value: &serde_yaml_ng::Value) -> bool {
    match value {
        serde_yaml_ng::Value::Mapping(map) => map.keys().any(|key| match key {
            serde_yaml_ng::Value::String(key) => RECOGNISED_TOP_LEVEL_KEYS.contains(&key.as_str()),
            _ => false,
        }),
        _ => false,
    }
}

pub fn yaml_from_string(config: &str) -> Result<common::Config> {
    // Parse into a generic value first so the document shape can be checked
    // before it is handed to serde. See `RECOGNISED_TOP_LEVEL_KEYS`.
    let value: serde_yaml_ng::Value = serde_yaml_ng::from_str(config)
        .map_err(|e| anyhow!("deserialize yaml config failed: {}", e))?;
    if !is_leaf_config_mapping(&value) {
        return Err(anyhow!(
            "deserialize yaml config failed: not a mapping with a recognised top-level key"
        ));
    }
    let config: common::Config = serde_yaml_ng::from_value(value)
        .map_err(|e| anyhow!("deserialize yaml config failed: {}", e))?;
    apply_env(&config);
    Ok(config)
}

pub fn from_string(s: &str) -> Result<internal::Config> {
    let config = yaml_from_string(s)?;
    common::to_internal(config)
}

pub fn from_file<P>(path: P) -> Result<internal::Config>
where
    P: AsRef<Path>,
{
    let config = std::fs::read_to_string(path)?;
    let config = yaml_from_string(&config)?;
    common::to_internal(config)
}
