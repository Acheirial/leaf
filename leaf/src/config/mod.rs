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
    // YAML is the preferred format. `yaml::from_string` only accepts a document
    // that is a mapping carrying a recognised top-level key, so clash-style
    // `.conf` text (which parses as YAML) is not silently swallowed here and
    // still reaches the conf parser below.
    #[cfg(feature = "config-yaml")]
    {
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
    Err(anyhow!("config files use extension .yml, .yaml, .json or .conf"))
}
