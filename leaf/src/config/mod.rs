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
    #[cfg(feature = "config-json")]
    {
        if let Ok(c) = json::from_string(s) {
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
                #[cfg(feature = "config-json")]
                "json" => return json::from_file(path),
                #[cfg(feature = "config-conf")]
                "conf" => return conf::from_file(path),
                _ => (),
            }
        }
    }
    Err(anyhow!("config files use extension .json or .conf"))
}
