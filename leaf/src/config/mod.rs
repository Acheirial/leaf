use std::path::Path;

use anyhow::anyhow;
use anyhow::Result;

pub mod common;
pub mod external_rule;
pub mod geosite;
pub mod internal;

#[cfg(feature = "config-json")]
pub mod json;

#[cfg(feature = "config-conf")]
pub mod conf;

#[cfg(feature = "config-yaml")]
pub mod yaml;

pub use internal::*;

/// Top-level keys that mark a YAML document as a leaf configuration. Kept in
/// sync with `crate::config::yaml`'s own `RECOGNISED_TOP_LEVEL_KEYS`.
#[cfg(feature = "config-yaml")]
const YAML_TOP_LEVEL_KEYS: &[&str] = &["inbounds", "outbounds", "dns", "log", "router", "api"];

/// Whether the first meaningful line of `s` — the first non-blank, non-comment
/// line — is one of [`YAML_TOP_LEVEL_KEYS`] followed by `:`.
#[cfg(feature = "config-yaml")]
fn first_line_is_yaml_key(s: &str) -> bool {
    let line = s.lines().find(|line| {
        let trimmed = line.trim();
        !trimmed.is_empty() && !trimmed.starts_with('#')
    });
    let Some(line) = line else {
        return false;
    };
    YAML_TOP_LEVEL_KEYS.iter().any(|key| {
        line.strip_prefix(key)
            .is_some_and(|rest| rest.trim_start().starts_with(':'))
    })
}

/// Whether `s` is clearly *meant* to be YAML: it carries the `---` document
/// marker, or its first meaningful line is a recognised top-level key. Such
/// documents are routed straight to the YAML parser so a malformed one fails
/// loudly instead of being swallowed by the conf parser. See [`from_string`].
#[cfg(feature = "config-yaml")]
fn looks_like_yaml(s: &str) -> bool {
    s.trim_start().starts_with("---") || first_line_is_yaml_key(s)
}

pub fn from_string(s: &str) -> Result<internal::Config> {
    // JSON configs are always objects, so an input beginning with `{` is
    // unambiguously JSON. Parse it directly and propagate errors instead of
    // silently falling through to the conf parser (which would accept
    // arbitrary text and produce an empty config).
    if s.trim_start().starts_with('{') {
        #[cfg(feature = "config-json")]
        {
            return json::from_string(s);
        }
        #[cfg(not(feature = "config-json"))]
        {
            return Err(anyhow!("json config is not supported by this build"));
        }
    }
    // A JSON array is valid JSON but never a valid leaf config. Try JSON first
    // for `[`-prefixed input, yet fall through when it is not JSON, because
    // clash-style `.conf` files start with a `[Section]` header.
    #[cfg(feature = "config-json")]
    {
        if s.trim_start().starts_with('[') {
            if let Ok(c) = json::from_string(s) {
                return Ok(c);
            }
        }
    }
    // YAML is the preferred format. A document that is *meant* to be YAML must
    // be parsed as YAML so a malformed one errors instead of falling through to
    // the conf parser, which accepts arbitrary text and would return an empty
    // config (the same failure mode fixed for JSON above). "Meant to be YAML" is
    // recognised heuristically by `looks_like_yaml`.
    #[cfg(feature = "config-yaml")]
    {
        if looks_like_yaml(s) {
            return yaml::from_string(s);
        }
        // Not clearly YAML: keep the old fall-through, since clash-style `.conf`
        // text (which parses as YAML) must still reach the conf parser below.
        if let Ok(c) = yaml::from_string(s) {
            return Ok(c);
        }
    }
    #[cfg(feature = "config-conf")]
    {
        return conf::from_string(s);
    }
    #[allow(unreachable_code)]
    Err(anyhow!("could not load config from:\n{:?}", s))
}

pub fn from_file(path: &str) -> Result<internal::Config> {
    if let Some(ext) = Path::new(path).extension() {
        if let Some(ext) = ext.to_str() {
            match ext {
                #[cfg(feature = "config-yaml")]
                "yml" | "yaml" => return yaml::from_file(path),
                #[cfg(feature = "config-json")]
                "json" => return json::from_file(path),
                #[cfg(feature = "config-conf")]
                "conf" => return conf::from_file(path),
                _ => (),
            }
        }
    }
    Err(anyhow!(
        "config files use extension .yml, .yaml, .json or .conf"
    ))
}

#[cfg(test)]
mod tests {
    /// A document that is clearly YAML (recognised top-level key) but is
    /// syntactically broken must error, not silently become an empty conf.
    #[cfg(feature = "config-yaml")]
    #[test]
    fn malformed_yaml_is_an_error() {
        let malformed = "inbounds:\n  - tag: \"unterminated\n    port: 1086\n";
        assert!(
            super::from_string(malformed).is_err(),
            "malformed YAML must not parse into an empty config"
        );
    }

    #[cfg(feature = "config-yaml")]
    #[test]
    fn valid_yaml_still_parses() {
        let yaml = "inbounds:\n  - tag: socks_in\n    address: 127.0.0.1\n    port: 1086\n    protocol: socks\n";
        let config = super::from_string(yaml).expect("valid YAML should parse");
        assert_eq!(config.inbounds.len(), 1);
        assert_eq!(config.inbounds[0].protocol, "socks");
        assert_eq!(config.inbounds[0].tag, "socks_in");
    }

    /// Clash-style `.conf` text is valid YAML syntactically but not a leaf
    /// config; it must still be routed to the conf parser.
    #[cfg(all(feature = "config-yaml", feature = "config-conf"))]
    #[test]
    fn clash_conf_still_routes_to_conf() {
        let conf = "[General]\nloglevel = info\ndns-server = 8.8.8.8\n";
        let routed = super::from_string(conf).expect("conf should route");
        let direct = super::conf::from_string(conf).expect("conf should parse");
        assert_eq!(routed, direct);
    }

    /// Malformed JSON (leading `{`) must error rather than fall through.
    #[cfg(feature = "config-json")]
    #[test]
    fn malformed_json_is_an_error() {
        let malformed = "{\"inbounds\": [}";
        assert!(
            super::from_string(malformed).is_err(),
            "malformed JSON must not parse into an empty config"
        );
    }
}
