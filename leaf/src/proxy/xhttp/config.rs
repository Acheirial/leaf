//! The XHTTP config, parsed out of leaf's protobuf settings plus the raw Xray
//! JSON that `extra` (and `downloadSettings`) carry.
//!
//! Xray's JSON front matter normalizes its `SplitHTTPConfig` before it becomes
//! the protobuf `Config`, and it is that normalized form that lands in `extra`.
//! When `extra` is present it *replaces* every other field except `host`,
//! `path` and `mode`, which the outer settings still win -- the same rule the
//! Xray conf loader applies. `Config` therefore keeps the normalized values and
//! the `normalized_*` accessors mirror the accessors on Xray's `Config` for the
//! cases where a value can still be absent (an `extra` that omits a field, or a
//! directly built protobuf).

use anyhow::{anyhow, Result};
use rand::Rng;
use serde_json::Value;

use crate::config;

/// The value a placement field uses when nothing says otherwise.
pub const PLACEMENT_QUERY_IN_HEADER: &str = "queryInHeader";
pub const PLACEMENT_COOKIE: &str = "cookie";
pub const PLACEMENT_HEADER: &str = "header";
pub const PLACEMENT_QUERY: &str = "query";
pub const PLACEMENT_PATH: &str = "path";
pub const PLACEMENT_BODY: &str = "body";
pub const PLACEMENT_AUTO: &str = "auto";

pub const MODE_AUTO: &str = "auto";
pub const MODE_PACKET_UP: &str = "packet-up";
pub const MODE_STREAM_UP: &str = "stream-up";
pub const MODE_STREAM_ONE: &str = "stream-one";

/// Xray's `RangeConfig`: an inclusive `[from, to]` a random value is drawn
/// from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RangeConfig {
    pub from: i64,
    pub to: i64,
}

impl RangeConfig {
    pub fn value(&self) -> i64 {
        // crypto.RandBetween(from, to) is inclusive and tolerates from == to.
        if self.to <= self.from {
            return self.from;
        }
        let mut rng = rand::thread_rng();
        rng.gen_range(self.from..=self.to)
    }

    pub fn is_zero(&self) -> bool {
        self.from == 0 && self.to == 0
    }
}

#[derive(Debug, Clone, Default)]
pub struct XmuxConfig {
    pub max_concurrency: Option<RangeConfig>,
    pub max_connections: Option<RangeConfig>,
    pub c_max_reuse_times: Option<RangeConfig>,
    pub h_max_request_times: Option<RangeConfig>,
    pub h_max_reusable_secs: Option<RangeConfig>,
    pub h_keep_alive_period: i64,
}

#[derive(Debug, Clone)]
pub struct Config {
    pub host: String,
    pub path: String,
    pub mode: String,
    pub headers: Vec<(String, String)>,
    pub x_padding_bytes: Option<RangeConfig>,
    pub x_padding_obfs_mode: bool,
    pub x_padding_key: String,
    pub x_padding_header: String,
    pub x_padding_placement: String,
    pub x_padding_method: String,
    pub no_grpc_header: bool,
    pub no_sse_header: bool,
    pub sc_max_each_post_bytes: Option<RangeConfig>,
    pub sc_min_posts_interval_ms: Option<RangeConfig>,
    pub sc_max_buffered_posts: i64,
    pub sc_stream_up_server_secs: Option<RangeConfig>,
    pub xmux: XmuxConfig,
    pub download_settings: Option<Value>,
    pub uplink_http_method: String,
    pub session_id_placement: String,
    pub session_id_key: String,
    pub seq_placement: String,
    pub seq_key: String,
    pub uplink_data_placement: String,
    pub uplink_data_key: String,
    pub uplink_chunk_size: Option<RangeConfig>,
    pub server_max_header_bytes: i64,
    pub session_id_table: String,
    pub session_id_length: Option<RangeConfig>,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            host: String::new(),
            path: String::new(),
            mode: String::new(),
            headers: Vec::new(),
            x_padding_bytes: None,
            x_padding_obfs_mode: false,
            x_padding_key: String::new(),
            x_padding_header: String::new(),
            x_padding_placement: String::new(),
            x_padding_method: String::new(),
            no_grpc_header: false,
            no_sse_header: false,
            sc_max_each_post_bytes: None,
            sc_min_posts_interval_ms: None,
            sc_max_buffered_posts: 0,
            sc_stream_up_server_secs: None,
            xmux: XmuxConfig::default(),
            download_settings: None,
            uplink_http_method: String::new(),
            session_id_placement: String::new(),
            session_id_key: String::new(),
            seq_placement: String::new(),
            seq_key: String::new(),
            uplink_data_placement: String::new(),
            uplink_data_key: String::new(),
            uplink_chunk_size: None,
            server_max_header_bytes: 0,
            session_id_table: String::new(),
            session_id_length: None,
        }
    }
}

impl Config {
    pub fn from_inbound(settings: &config::XhttpInboundSettings) -> Result<Config> {
        let mut c = Config::default();
        c.host = settings.host.clone().unwrap_or_default();
        c.path = settings.path.clone().unwrap_or_default();
        c.mode = settings.mode.clone().unwrap_or_default();

        if let Some(extra) = settings.extra.as_deref() {
            if !extra.trim().is_empty() {
                c.apply_extra(extra)?;
            }
        }

        if let Some(download) = settings.download_settings.as_deref() {
            if !download.trim().is_empty() {
                let v: Value = serde_json::from_str(download)
                    .map_err(|e| anyhow!("invalid xhttp downloadSettings: {}", e))?;
                c.download_settings = Some(v);
            }
        }

        c.validate()?;
        Ok(c)
    }

    pub fn from_outbound(settings: &config::XhttpOutboundSettings) -> Result<Config> {
        let mut c = Config::default();
        c.host = settings.host.clone().unwrap_or_default();
        c.path = settings.path.clone().unwrap_or_default();
        c.mode = settings.mode.clone().unwrap_or_default();

        if let Some(extra) = settings.extra.as_deref() {
            if !extra.trim().is_empty() {
                c.apply_extra(extra)?;
            }
        }

        c.validate()?;
        Ok(c)
    }

    fn apply_extra(&mut self, extra: &str) -> Result<()> {
        let v: Value =
            serde_json::from_str(extra).map_err(|e| anyhow!("invalid xhttp extra: {}", e))?;
        self.apply_extra_value(&v)
    }

    fn apply_extra_value(&mut self, v: &Value) -> Result<()> {
        let obj = v
            .as_object()
            .ok_or_else(|| anyhow!("invalid xhttp extra: expected a JSON object"))?;

        if let Some(headers) = obj.get("headers").and_then(|v| v.as_object()) {
            self.headers = headers
                .iter()
                .filter_map(|(k, v)| v.as_str().map(|v| (k.clone(), v.to_string())))
                .collect();
        }
        self.x_padding_bytes = get_range(obj, "xPaddingBytes");
        self.x_padding_obfs_mode = get_bool(obj, "xPaddingObfsMode").unwrap_or(false);
        self.x_padding_key = get_str(obj, "xPaddingKey").unwrap_or_default();
        self.x_padding_header = get_str(obj, "xPaddingHeader").unwrap_or_default();
        self.x_padding_placement = get_str(obj, "xPaddingPlacement").unwrap_or_default();
        self.x_padding_method = get_str(obj, "xPaddingMethod").unwrap_or_default();
        self.no_grpc_header = get_bool(obj, "noGRPCHeader").unwrap_or(false);
        self.no_sse_header = get_bool(obj, "noSSEHeader").unwrap_or(false);
        self.sc_max_each_post_bytes = get_range(obj, "scMaxEachPostBytes");
        self.sc_min_posts_interval_ms = get_range(obj, "scMinPostsIntervalMs");
        self.sc_max_buffered_posts = get_i64(obj, "scMaxBufferedPosts").unwrap_or(0);
        self.sc_stream_up_server_secs = get_range(obj, "scStreamUpServerSecs");
        self.uplink_http_method = get_str(obj, "uplinkHTTPMethod").unwrap_or_default();
        self.session_id_placement = get_str(obj, "sessionIDPlacement").unwrap_or_default();
        self.session_id_key = get_str(obj, "sessionIDKey").unwrap_or_default();
        self.session_id_table = get_str(obj, "sessionIDTable").unwrap_or_default();
        self.session_id_length = get_range(obj, "sessionIDLength");
        self.seq_placement = get_str(obj, "seqPlacement").unwrap_or_default();
        self.seq_key = get_str(obj, "seqKey").unwrap_or_default();
        self.uplink_data_placement = get_str(obj, "uplinkDataPlacement").unwrap_or_default();
        self.uplink_data_key = get_str(obj, "uplinkDataKey").unwrap_or_default();
        self.uplink_chunk_size = get_range(obj, "uplinkChunkSize");
        self.server_max_header_bytes = get_i64(obj, "serverMaxHeaderBytes").unwrap_or(0);

        if let Some(xmux) = obj.get("xmux").and_then(|v| v.as_object()) {
            self.xmux = XmuxConfig {
                max_concurrency: get_range(xmux, "maxConcurrency"),
                max_connections: get_range(xmux, "maxConnections"),
                c_max_reuse_times: get_range(xmux, "cMaxReuseTimes"),
                h_max_request_times: get_range(xmux, "hMaxRequestTimes"),
                h_max_reusable_secs: get_range(xmux, "hMaxReusableSecs"),
                h_keep_alive_period: get_i64(xmux, "hKeepAlivePeriod").unwrap_or(0),
            };
        }

        Ok(())
    }

    /// Mirrors Xray's `SplitHTTPConfig.Build` checks for the fields this port
    /// can act on.
    fn validate(&mut self) -> Result<()> {
        if self.mode.is_empty() {
            self.mode = MODE_AUTO.to_string();
        }
        match self.mode.as_str() {
            MODE_AUTO | MODE_PACKET_UP | MODE_STREAM_UP | MODE_STREAM_ONE => {}
            other => return Err(anyhow!("unsupported xhttp mode: {}", other)),
        }

        for (k, _) in self.headers.iter() {
            if k.eq_ignore_ascii_case("host") {
                return Err(anyhow!("\"headers\" can't contain \"host\""));
            }
        }

        if let Some(r) = self.x_padding_bytes {
            if r.from <= 0 || r.to <= 0 {
                return Err(anyhow!("xPaddingBytes cannot be disabled"));
            }
        }

        if self.x_padding_key.is_empty() {
            self.x_padding_key = "x_padding".to_string();
        }
        if self.x_padding_header.is_empty() {
            self.x_padding_header = "X-Padding".to_string();
        }
        if self.x_padding_placement.is_empty() {
            self.x_padding_placement = PLACEMENT_QUERY_IN_HEADER.to_string();
        }
        match self.x_padding_placement.as_str() {
            PLACEMENT_COOKIE | PLACEMENT_HEADER | PLACEMENT_QUERY | PLACEMENT_QUERY_IN_HEADER => {}
            other => return Err(anyhow!("unsupported padding placement: {}", other)),
        }
        if self.x_padding_method.is_empty() {
            self.x_padding_method = "repeat-x".to_string();
        }
        match self.x_padding_method.as_str() {
            "repeat-x" | "tokenish" => {}
            other => return Err(anyhow!("unsupported padding method: {}", other)),
        }

        if self.uplink_data_placement.is_empty() {
            self.uplink_data_placement = PLACEMENT_AUTO.to_string();
        }
        match self.uplink_data_placement.as_str() {
            PLACEMENT_AUTO | PLACEMENT_BODY => {}
            PLACEMENT_COOKIE | PLACEMENT_HEADER => {
                if self.mode != MODE_PACKET_UP {
                    return Err(anyhow!(
                        "uplinkDataPlacement can be {} only in packet-up mode",
                        self.uplink_data_placement
                    ));
                }
            }
            other => return Err(anyhow!("unsupported uplink data placement: {}", other)),
        }

        if self.uplink_http_method.is_empty() {
            self.uplink_http_method = "POST".to_string();
        }
        self.uplink_http_method = self.uplink_http_method.to_uppercase();
        if self.uplink_http_method == "GET" && self.mode != MODE_PACKET_UP {
            return Err(anyhow!(
                "uplinkHTTPMethod can be GET only in packet-up mode"
            ));
        }

        if self.session_id_placement.is_empty() {
            self.session_id_placement = PLACEMENT_PATH.to_string();
        }
        match self.session_id_placement.as_str() {
            PLACEMENT_PATH | PLACEMENT_COOKIE | PLACEMENT_HEADER | PLACEMENT_QUERY => {}
            other => return Err(anyhow!("unsupported session placement: {}", other)),
        }
        if self.seq_placement.is_empty() {
            self.seq_placement = PLACEMENT_PATH.to_string();
        }
        match self.seq_placement.as_str() {
            PLACEMENT_PATH | PLACEMENT_COOKIE | PLACEMENT_HEADER | PLACEMENT_QUERY => {}
            other => return Err(anyhow!("unsupported seq placement: {}", other)),
        }

        if self.session_id_placement != PLACEMENT_PATH && self.session_id_key.is_empty() {
            self.session_id_key = match self.session_id_placement.as_str() {
                PLACEMENT_COOKIE | PLACEMENT_QUERY => "x_session".to_string(),
                PLACEMENT_HEADER => "X-Session".to_string(),
                _ => String::new(),
            };
        }
        if self.seq_placement != PLACEMENT_PATH && self.seq_key.is_empty() {
            self.seq_key = match self.seq_placement.as_str() {
                PLACEMENT_COOKIE | PLACEMENT_QUERY => "x_seq".to_string(),
                PLACEMENT_HEADER => "X-Seq".to_string(),
                _ => String::new(),
            };
        }
        if self.uplink_data_placement != PLACEMENT_BODY && self.uplink_data_key.is_empty() {
            self.uplink_data_key = match self.uplink_data_placement.as_str() {
                PLACEMENT_COOKIE => "x_data".to_string(),
                PLACEMENT_AUTO | PLACEMENT_HEADER => "X-Data".to_string(),
                _ => String::new(),
            };
        }

        if self.server_max_header_bytes < 0 {
            return Err(anyhow!("invalid negative value of serverMaxHeaderBytes"));
        }

        if let (Some(mc), Some(mx)) = (self.xmux.max_connections, self.xmux.max_concurrency) {
            if mc.to > 0 && mx.to > 0 {
                return Err(anyhow!(
                    "maxConnections cannot be specified together with maxConcurrency"
                ));
            }
        }

        if !self.session_id_table.is_empty() {
            if let Some(predefined) = predefined_table(&self.session_id_table) {
                self.session_id_table = predefined.to_string();
            }
            let from = self.session_id_length.map(|r| r.from).unwrap_or(0);
            if from <= 0 {
                return Err(anyhow!("sessionIDLength.from must be greater than 0"));
            }
            if !self.session_id_table.is_ascii() {
                return Err(anyhow!("sessionIDTable must contain only ASCII characters"));
            }
        }

        Ok(())
    }

    // --- normalized getters, mirroring the accessors on Xray's Config ---

    pub fn normalized_path(&self) -> String {
        let path = match self.path.split_once('?') {
            Some((p, _)) => p.to_string(),
            None => self.path.clone(),
        };
        let mut path = if path.is_empty() || !path.starts_with('/') {
            format!("/{}", path)
        } else {
            path
        };
        if (self.normalized_session_placement() == PLACEMENT_PATH
            || self.normalized_seq_placement() == PLACEMENT_PATH)
            && !path.ends_with('/')
        {
            path.push('/');
        }
        path
    }

    pub fn normalized_query(&self) -> String {
        match self.path.split_once('?') {
            Some((_, q)) => q.to_string(),
            None => String::new(),
        }
    }

    pub fn normalized_uplink_http_method(&self) -> String {
        if self.uplink_http_method.is_empty() {
            "POST".to_string()
        } else {
            self.uplink_http_method.clone()
        }
    }

    pub fn normalized_sc_max_each_post_bytes(&self) -> RangeConfig {
        match self.sc_max_each_post_bytes {
            Some(r) if r.to != 0 => r,
            _ => RangeConfig {
                from: 1000000,
                to: 1000000,
            },
        }
    }

    pub fn normalized_sc_min_posts_interval_ms(&self) -> RangeConfig {
        match self.sc_min_posts_interval_ms {
            Some(r) if r.to != 0 => r,
            _ => RangeConfig { from: 30, to: 30 },
        }
    }

    pub fn normalized_sc_max_buffered_posts(&self) -> usize {
        if self.sc_max_buffered_posts == 0 {
            30
        } else {
            self.sc_max_buffered_posts as usize
        }
    }

    pub fn normalized_sc_stream_up_server_secs(&self) -> RangeConfig {
        match self.sc_stream_up_server_secs {
            Some(r) if r.to != 0 => r,
            _ => RangeConfig { from: 20, to: 80 },
        }
    }

    pub fn normalized_uplink_chunk_size(&self) -> RangeConfig {
        match self.uplink_chunk_size {
            Some(r) if r.to != 0 => {
                if r.from < 64 {
                    RangeConfig {
                        from: 64,
                        to: r.to.max(64),
                    }
                } else {
                    r
                }
            }
            _ => match self.uplink_data_placement.as_str() {
                PLACEMENT_COOKIE => RangeConfig {
                    from: 2 * 1024,
                    to: 3 * 1024,
                },
                PLACEMENT_HEADER => RangeConfig {
                    from: 3 * 1000,
                    to: 4 * 1000,
                },
                _ => self.normalized_sc_max_each_post_bytes(),
            },
        }
    }

    pub fn normalized_server_max_header_bytes(&self) -> usize {
        if self.server_max_header_bytes <= 0 {
            8192
        } else {
            self.server_max_header_bytes as usize
        }
    }

    pub fn normalized_x_padding_bytes(&self) -> RangeConfig {
        match self.x_padding_bytes {
            Some(r) if r.to != 0 => r,
            _ => RangeConfig {
                from: 100,
                to: 1000,
            },
        }
    }

    pub fn normalized_session_placement(&self) -> &str {
        if self.session_id_placement.is_empty() {
            PLACEMENT_PATH
        } else {
            &self.session_id_placement
        }
    }

    pub fn normalized_seq_placement(&self) -> &str {
        if self.seq_placement.is_empty() {
            PLACEMENT_PATH
        } else {
            &self.seq_placement
        }
    }

    pub fn normalized_session_key(&self) -> String {
        if !self.session_id_key.is_empty() {
            return self.session_id_key.clone();
        }
        match self.normalized_session_placement() {
            PLACEMENT_HEADER => "X-Session".to_string(),
            PLACEMENT_COOKIE | PLACEMENT_QUERY => "x_session".to_string(),
            _ => String::new(),
        }
    }

    pub fn normalized_seq_key(&self) -> String {
        if !self.seq_key.is_empty() {
            return self.seq_key.clone();
        }
        match self.normalized_seq_placement() {
            PLACEMENT_HEADER => "X-Seq".to_string(),
            PLACEMENT_COOKIE | PLACEMENT_QUERY => "x_seq".to_string(),
            _ => String::new(),
        }
    }

    pub fn normalized_uplink_data_placement(&self) -> &str {
        if self.uplink_data_placement.is_empty() {
            PLACEMENT_BODY
        } else {
            &self.uplink_data_placement
        }
    }

    /// The mode actually used for a dial. `auto` is `packet-up` for a plain
    /// HTTP/1.1 stream, which is what this port always speaks.
    pub fn resolved_mode(&self) -> String {
        match self.mode.as_str() {
            "" | MODE_AUTO => MODE_PACKET_UP.to_string(),
            other => other.to_string(),
        }
    }

    pub fn generate_session_id(&self) -> String {
        let length = self.session_id_length.map(|r| r.value()).unwrap_or(0);
        let table = if self.session_id_table.is_empty() {
            ""
        } else {
            self.session_id_table.as_str()
        };
        if !table.is_empty() && length > 0 {
            let chars: Vec<char> = table.chars().collect();
            let mut rng = rand::thread_rng();
            (0..length)
                .map(|_| chars[rng.gen_range(0..chars.len())])
                .collect()
        } else {
            uuid::Uuid::new_v4().to_string()
        }
    }
}

fn get_str(obj: &serde_json::Map<String, Value>, key: &str) -> Option<String> {
    obj.get(key).and_then(|v| v.as_str()).map(|s| s.to_string())
}

fn get_bool(obj: &serde_json::Map<String, Value>, key: &str) -> Option<bool> {
    obj.get(key).and_then(|v| v.as_bool())
}

fn get_i64(obj: &serde_json::Map<String, Value>, key: &str) -> Option<i64> {
    obj.get(key).and_then(|v| v.as_i64())
}

fn get_range(obj: &serde_json::Map<String, Value>, key: &str) -> Option<RangeConfig> {
    let v = obj.get(key)?;
    if v.is_null() {
        return None;
    }
    if let Some(n) = v.as_i64() {
        return Some(RangeConfig { from: n, to: n });
    }
    let from = v.get("from").and_then(|x| x.as_i64()).unwrap_or(0);
    let to = v.get("to").and_then(|x| x.as_i64()).unwrap_or(0);
    Some(RangeConfig { from, to })
}

fn predefined_table(name: &str) -> Option<&'static str> {
    Some(match name {
        "ALPHABET" => "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
        "Alphabet" => "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
        "BASE36" => "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ",
        "Base62" => "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
        "HEX" => "0123456789ABCDEF",
        "alphabet" => "abcdefghijklmnopqrstuvwxyz",
        "base36" => "0123456789abcdefghijklmnopqrstuvwxyz",
        "hex" => "0123456789abcdef",
        "number" => "0123456789",
        _ => return None,
    })
}
