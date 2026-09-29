//! The TCP and UDP `header-custom` masks.
//!
//! A `header-custom` mask prepends a programmatically built header to the
//! protocol bytes (a TCP byte stream or a UDP datagram) and verifies the same
//! header on the peer. The header is described by JSON, mirroring Xray's
//! `HeaderCustomTCP`/`HeaderCustomUDP` configuration:
//!
//! ```json
//! {
//!   "clients": [[{ "packet": [1, 2, 3] }]],
//!   "servers": [[{ "rand": 8 }]],
//!   "errors":  [[{ "packet": "HTTP/1.1 404 Not Found\r\n" }]]
//! }
//! ```
//!
//! Each header item is exactly one of:
//!
//! * `packet` — a fixed byte string (the `type` field selects `array`, `str`
//!   or `hex`; base64 is not part of this subset).
//! * `rand` — a random-length body (`randRange` gives `[from, to]`, default
//!   `0..=255`). Random bodies are not verified when read.
//! * `reuse` — the bytes saved earlier under a variable name by `capture`.
//! * `transform` — an expression, see below.
//!
//! `capture` saves the produced (write) or read bytes under a name for a later
//! item to `reuse`.
//!
//! # Expressions
//!
//! A `transform` is `{ "op": String, "args": [arg, ...] }`, where each arg sets
//! exactly one of `bytes`, `u64`, `reuse`, `metadata` or a nested `transform`.
//! Values are either byte strings or `u64`; the following ops are supported,
//! and no other op is accepted:
//!
//! * byte ops: `concat`, `slice`, `xor16`, `xor32`, `be16`, `be32`, `le16`,
//!   `le32`, `le64`, `pad`, `truncate`
//! * integer ops: `add`, `sub`, `and`, `or`, `shl`, `shr`
//!
//! `beXX`/`leXX` pack a `u64` into bytes (rejecting values that do not fit the
//! width), `xor16`/`xor32` mask the result to 16/32 bits, and `slice`,
//! `pad`, `truncate`, `shl` and the arithmetic check their bounds exactly as
//! Xray's evaluator does.
//!
//! `metadata` reads a connection address: `local_port`, `remote_port`,
//! `src_port_u16`, `dst_port_u16`, `local_ip4_u32`, `remote_ip4_u32`,
//! `src_ip4_u32`, `dst_ip4_u32`. Each is present only when the matching
//! address is known (UDP packets carry them via [`PacketMeta`]); a reference to
//! one that is absent is an error. TCP has no address source in this framework,
//! so TCP expressions can use neither metadata nor `metadata`-backed ops.
//!
//! # TCP handshake
//!
//! On the client the first write runs the handshake: it writes each `clients[i]`
//! sequence, verifying a `servers[j]` reply when one exists, and then consumes
//! any remaining `servers` sequences. On the server the first read mirrors it:
//! each `clients[i]` is read and verified (writing the matching `errors[i]` when
//! configured and verification fails), replying with `servers[j]` when present,
//! then consuming the remaining `servers`. Once the handshake succeeds every
//! later read and write passes through. Reading before authentication, or
//! writing before authentication on the server, is an error.
//!
//! # UDP
//!
//! The mask is bound to one role. On the client the `client` list builds the
//! header on encode and the `server` list verifies and strips it on decode; on
//! the server the lists swap. The fixed header size of each list is measured at
//! construction; a header whose evaluation is not exactly that size, or that
//! fails to match, drops the packet. Per-peer saved variables live in a store
//! with a 5-second TTL, as in Xray.

use std::collections::HashMap;
use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use parking_lot::Mutex;
use serde_derive::Deserialize;
use serde_json::Value;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

use crate::proxy::finalmask::{parse_byte_slice, rand_between, rand_bytes_between, FinalmaskError};
use crate::proxy::AnyStream;

use super::{PacketMeta, Role, TcpMask, TcpMaskFactory, UdpMask, UdpMaskFactory};

/// The name used in every [`FinalmaskError::Invalid`] this module returns.
const MASK: &str = "header-custom";

/// The expression ops this mask understands; any other op is rejected at
/// construction.
const SUPPORTED_OPS: [&str; 17] = [
    "concat", "slice", "xor16", "xor32", "be16", "be32", "le16", "le32", "le64", "pad", "truncate",
    "add", "sub", "and", "or", "shl", "shr",
];

fn invalid(reason: impl std::fmt::Display) -> FinalmaskError {
    FinalmaskError::Invalid {
        mask: MASK.to_string(),
        reason: reason.to_string(),
    }
}

fn io_err(reason: impl std::fmt::Display) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, reason.to_string())
}

// --- expression values -----------------------------------------------------

#[derive(Clone, Debug)]
enum EvalValue {
    Bytes(Vec<u8>),
    U64(u64),
}

impl EvalValue {
    fn as_bytes(&self) -> Result<Vec<u8>, io::Error> {
        match self {
            EvalValue::Bytes(b) => Ok(b.clone()),
            EvalValue::U64(_) => Err(io_err("expr value is not bytes")),
        }
    }

    fn as_u64(&self) -> Result<u64, io::Error> {
        match self {
            EvalValue::U64(v) => Ok(*v),
            EvalValue::Bytes(_) => Err(io_err("expr value is not u64")),
        }
    }
}

#[derive(Clone, Debug)]
struct Expr {
    op: String,
    args: Vec<ExprArg>,
}

#[derive(Clone, Debug)]
enum ExprArg {
    Bytes(Vec<u8>),
    U64(u64),
    Var(String),
    Metadata(String),
    Expr(Box<Expr>),
}

#[derive(Clone, Default)]
struct EvalContext {
    vars: HashMap<String, Vec<u8>>,
    metadata: HashMap<String, EvalValue>,
}

impl EvalContext {
    fn new() -> Self {
        Self::default()
    }

    fn with_meta(meta: &PacketMeta) -> Self {
        let mut ctx = Self::default();
        load_metadata(&mut ctx.metadata, "local", meta.local);
        load_metadata(&mut ctx.metadata, "remote", meta.remote);
        ctx
    }
}

fn load_metadata(dst: &mut HashMap<String, EvalValue>, prefix: &str, addr: Option<SocketAddr>) {
    let Some(addr) = addr else {
        return;
    };
    let port = addr.port() as u64;
    dst.insert(format!("{}_port", prefix), EvalValue::U64(port));
    if prefix == "remote" {
        dst.insert("src_port_u16".to_string(), EvalValue::U64(port));
    } else if prefix == "local" {
        dst.insert("dst_port_u16".to_string(), EvalValue::U64(port));
    }
    if let SocketAddr::V4(v4) = addr {
        let ip = u32::from_be_bytes(v4.ip().octets()) as u64;
        dst.insert(format!("{}_ip4_u32", prefix), EvalValue::U64(ip));
        if prefix == "remote" {
            dst.insert("src_ip4_u32".to_string(), EvalValue::U64(ip));
        } else if prefix == "local" {
            dst.insert("dst_ip4_u32".to_string(), EvalValue::U64(ip));
        }
    }
}

fn evaluate_expr(expr: &Expr, ctx: &EvalContext) -> Result<EvalValue, io::Error> {
    match expr.op.as_str() {
        "concat" => {
            let mut out = Vec::new();
            for arg in &expr.args {
                out.extend_from_slice(&evaluate_expr_arg(arg, ctx)?.as_bytes()?);
            }
            Ok(EvalValue::Bytes(out))
        }
        "slice" => {
            if expr.args.len() != 3 {
                return Err(io_err("slice expects 3 args"));
            }
            let source = evaluate_expr_arg(&expr.args[0], ctx)?.as_bytes()?;
            let offset = evaluate_expr_arg(&expr.args[1], ctx)?.as_u64()?;
            let length = evaluate_expr_arg(&expr.args[2], ctx)?.as_u64()?;
            let end = offset
                .checked_add(length)
                .ok_or_else(|| io_err("slice out of bounds"))?;
            if end > source.len() as u64 {
                return Err(io_err("slice out of bounds"));
            }
            Ok(EvalValue::Bytes(
                source[offset as usize..end as usize].to_vec(),
            ))
        }
        "xor16" => evaluate_xor(&expr.args, 0xFFFF, 2, ctx),
        "xor32" => evaluate_xor(&expr.args, 0xFFFF_FFFF, 4, ctx),
        "be16" => evaluate_pack(&expr.args, "be16", 2, true, ctx),
        "be32" => evaluate_pack(&expr.args, "be32", 4, true, ctx),
        "le16" => evaluate_pack(&expr.args, "le16", 2, false, ctx),
        "le32" => evaluate_pack(&expr.args, "le32", 4, false, ctx),
        "le64" => evaluate_pack(&expr.args, "le64", 8, false, ctx),
        "pad" => evaluate_pad(&expr.args, ctx),
        "truncate" => evaluate_truncate(&expr.args, ctx),
        "add" => evaluate_binary_u64(&expr.args, "add", ctx, |l, r| {
            l.checked_add(r).ok_or_else(|| io_err("add overflow"))
        }),
        "sub" => evaluate_binary_u64(&expr.args, "sub", ctx, |l, r| {
            l.checked_sub(r).ok_or_else(|| io_err("sub underflow"))
        }),
        "and" => evaluate_binary_u64(&expr.args, "and", ctx, |l, r| Ok(l & r)),
        "or" => evaluate_binary_u64(&expr.args, "or", ctx, |l, r| Ok(l | r)),
        "shl" => evaluate_shift(&expr.args, "shl", ctx, |value, shift| {
            if value > (u64::MAX >> shift) {
                return Err(io_err("shl overflow"));
            }
            Ok(value << shift)
        }),
        "shr" => evaluate_shift(&expr.args, "shr", ctx, |value, shift| Ok(value >> shift)),
        other => Err(io_err(format!("unsupported expr op: {}", other))),
    }
}

fn evaluate_pack(
    args: &[ExprArg],
    name: &str,
    width: usize,
    big: bool,
    ctx: &EvalContext,
) -> Result<EvalValue, io::Error> {
    if args.len() != 1 {
        return Err(io_err(format!("{} expects 1 arg", name)));
    }
    let value = evaluate_expr_arg(&args[0], ctx)?.as_u64()?;
    let bytes = match width {
        2 => {
            if value > 0xFFFF {
                return Err(io_err(format!("{} overflow", name)));
            }
            let v = value as u16;
            if big {
                v.to_be_bytes().to_vec()
            } else {
                v.to_le_bytes().to_vec()
            }
        }
        4 => {
            if value > 0xFFFF_FFFF {
                return Err(io_err(format!("{} overflow", name)));
            }
            let v = value as u32;
            if big {
                v.to_be_bytes().to_vec()
            } else {
                v.to_le_bytes().to_vec()
            }
        }
        8 => {
            if big {
                value.to_be_bytes().to_vec()
            } else {
                value.to_le_bytes().to_vec()
            }
        }
        _ => return Err(io_err("unsupported pack width")),
    };
    Ok(EvalValue::Bytes(bytes))
}

fn evaluate_pad(args: &[ExprArg], ctx: &EvalContext) -> Result<EvalValue, io::Error> {
    if args.len() != 3 {
        return Err(io_err("pad expects 3 args"));
    }
    let source = evaluate_expr_arg(&args[0], ctx)?.as_bytes()?;
    let target = evaluate_expr_arg(&args[1], ctx)?.as_u64()?;
    let fill = evaluate_expr_arg(&args[2], ctx)?.as_bytes()?;
    if fill.is_empty() {
        return Err(io_err("pad fill must not be empty"));
    }
    if target < source.len() as u64 {
        return Err(io_err("pad target shorter than source"));
    }
    let mut out = source;
    while (out.len() as u64) < target {
        let remaining = target as usize - out.len();
        if remaining >= fill.len() {
            out.extend_from_slice(&fill);
        } else {
            out.extend_from_slice(&fill[..remaining]);
        }
    }
    Ok(EvalValue::Bytes(out))
}

fn evaluate_truncate(args: &[ExprArg], ctx: &EvalContext) -> Result<EvalValue, io::Error> {
    if args.len() != 2 {
        return Err(io_err("truncate expects 2 args"));
    }
    let source = evaluate_expr_arg(&args[0], ctx)?.as_bytes()?;
    let length = evaluate_expr_arg(&args[1], ctx)?.as_u64()?;
    if length > source.len() as u64 {
        return Err(io_err("truncate out of bounds"));
    }
    Ok(EvalValue::Bytes(source[..length as usize].to_vec()))
}

fn evaluate_binary_u64(
    args: &[ExprArg],
    name: &str,
    ctx: &EvalContext,
    op: impl Fn(u64, u64) -> Result<u64, io::Error>,
) -> Result<EvalValue, io::Error> {
    if args.len() != 2 {
        return Err(io_err(format!("{} expects 2 args", name)));
    }
    let left = evaluate_expr_arg(&args[0], ctx)?.as_u64()?;
    let right = evaluate_expr_arg(&args[1], ctx)?.as_u64()?;
    Ok(EvalValue::U64(op(left, right)?))
}

fn evaluate_shift(
    args: &[ExprArg],
    name: &str,
    ctx: &EvalContext,
    op: impl Fn(u64, u32) -> Result<u64, io::Error>,
) -> Result<EvalValue, io::Error> {
    if args.len() != 2 {
        return Err(io_err(format!("{} expects 2 args", name)));
    }
    let value = evaluate_expr_arg(&args[0], ctx)?.as_u64()?;
    let shift = evaluate_expr_arg(&args[1], ctx)?.as_u64()?;
    if shift >= 64 {
        return Err(io_err("shift out of range"));
    }
    Ok(EvalValue::U64(op(value, shift as u32)?))
}

fn evaluate_xor(
    args: &[ExprArg],
    mask: u64,
    width: usize,
    ctx: &EvalContext,
) -> Result<EvalValue, io::Error> {
    if args.len() != 2 {
        return Err(io_err("xor expects 2 args"));
    }
    let left = evaluate_expr_arg(&args[0], ctx)?.as_u64()?;
    let right = evaluate_expr_arg(&args[1], ctx)?.as_u64()?;
    if width == 2 && (left > 0xFFFF || right > 0xFFFF) {
        return Err(io_err("xor16 overflow"));
    }
    if width == 4 && (left > 0xFFFF_FFFF || right > 0xFFFF_FFFF) {
        return Err(io_err("xor32 overflow"));
    }
    Ok(EvalValue::U64((left ^ right) & mask))
}

fn evaluate_expr_arg(arg: &ExprArg, ctx: &EvalContext) -> Result<EvalValue, io::Error> {
    match arg {
        ExprArg::Bytes(b) => Ok(EvalValue::Bytes(b.clone())),
        ExprArg::U64(v) => Ok(EvalValue::U64(*v)),
        ExprArg::Var(name) => ctx
            .vars
            .get(name)
            .cloned()
            .map(EvalValue::Bytes)
            .ok_or_else(|| io_err(format!("unknown variable: {}", name))),
        ExprArg::Metadata(key) => ctx
            .metadata
            .get(key)
            .cloned()
            .ok_or_else(|| io_err(format!("unknown metadata: {}", key))),
        ExprArg::Expr(expr) => evaluate_expr(expr, ctx),
    }
}

fn measure_expr(expr: &Expr, size_ctx: &HashMap<String, usize>) -> Result<usize, io::Error> {
    match expr.op.as_str() {
        "concat" => {
            let mut total = 0usize;
            for arg in &expr.args {
                total += measure_expr_arg(arg, size_ctx)?;
            }
            Ok(total)
        }
        "slice" => {
            if expr.args.len() != 3 {
                return Err(io_err("slice expects 3 args"));
            }
            match &expr.args[2] {
                ExprArg::U64(v) => Ok(*v as usize),
                _ => Err(io_err("slice length must be u64")),
            }
        }
        "be16" | "le16" => Ok(2),
        "be32" | "le32" => Ok(4),
        "le64" => Ok(8),
        "pad" => {
            if expr.args.len() != 3 {
                return Err(io_err("pad expects 3 args"));
            }
            match &expr.args[1] {
                ExprArg::U64(v) => Ok(*v as usize),
                _ => Err(io_err("pad length must be u64")),
            }
        }
        "truncate" => {
            if expr.args.len() != 2 {
                return Err(io_err("truncate expects 2 args"));
            }
            match &expr.args[1] {
                ExprArg::U64(v) => Ok(*v as usize),
                _ => Err(io_err("truncate length must be u64")),
            }
        }
        other => Err(io_err(format!("expr size is not bytes for op: {}", other))),
    }
}

fn measure_expr_arg(arg: &ExprArg, size_ctx: &HashMap<String, usize>) -> Result<usize, io::Error> {
    match arg {
        ExprArg::Bytes(b) => Ok(b.len()),
        ExprArg::U64(_) => Err(io_err("u64 arg has no byte width")),
        ExprArg::Var(name) => size_ctx
            .get(name)
            .copied()
            .ok_or_else(|| io_err(format!("unknown variable: {}", name))),
        ExprArg::Metadata(key) => Err(io_err(format!("metadata not implemented: {}", key))),
        ExprArg::Expr(expr) => measure_expr(expr, size_ctx),
    }
}

fn size_map(ctx: &EvalContext) -> HashMap<String, usize> {
    ctx.vars.iter().map(|(k, v)| (k.clone(), v.len())).collect()
}

// --- header items ----------------------------------------------------------

#[derive(Clone, Debug)]
struct Item {
    delay_min: i64,
    delay_max: i64,
    rand: i64,
    rand_min: u8,
    rand_max: u8,
    packet: Vec<u8>,
    save: String,
    var: String,
    expr: Option<Expr>,
}

impl Item {
    /// The wire size of this item, recording `save` in `size_ctx` so later
    /// items can reuse it. Mirrors Xray's `measureItem`.
    fn measure(&self, size_ctx: &mut HashMap<String, usize>) -> Result<usize, io::Error> {
        let size = if self.rand > 0 {
            self.rand as usize
        } else if !self.packet.is_empty() {
            self.packet.len()
        } else if !self.var.is_empty() {
            *size_ctx
                .get(&self.var)
                .ok_or_else(|| io_err(format!("unknown variable: {}", self.var)))?
        } else if let Some(expr) = &self.expr {
            measure_expr(expr, size_ctx)?
        } else {
            0
        };
        if !self.save.is_empty() {
            size_ctx.insert(self.save.clone(), size);
        }
        Ok(size)
    }

    /// The bytes this item contributes. Mirrors Xray's `evaluateItem`.
    fn evaluate(&self, ctx: &mut EvalContext) -> Result<Vec<u8>, io::Error> {
        let value = if self.rand > 0 {
            let mut buf = vec![0u8; self.rand as usize];
            rand_bytes_between(&mut buf, self.rand_min, self.rand_max);
            buf
        } else if !self.packet.is_empty() {
            self.packet.clone()
        } else if !self.var.is_empty() {
            ctx.vars
                .get(&self.var)
                .cloned()
                .ok_or_else(|| io_err(format!("unknown variable: {}", self.var)))?
        } else if let Some(expr) = &self.expr {
            evaluate_expr(expr, ctx)?.as_bytes()?
        } else {
            Vec::new()
        };
        if !self.save.is_empty() {
            ctx.vars.insert(self.save.clone(), value.clone());
        }
        Ok(value)
    }
}

fn evaluate_items(items: &[Item], ctx: &mut EvalContext) -> Result<Vec<u8>, io::Error> {
    let mut out = Vec::new();
    for item in items {
        out.extend_from_slice(&item.evaluate(ctx)?);
    }
    Ok(out)
}

fn measure_items(items: &[Item], fallback: &HashMap<String, usize>) -> Result<usize, io::Error> {
    let mut size_ctx = fallback.clone();
    let mut total = 0usize;
    for item in items {
        total += item.measure(&mut size_ctx)?;
    }
    Ok(total)
}

/// The sizes of the variables the items capture, used as the fallback size
/// context when measuring the peer list.
fn collect_saved_sizes(items: &[Item]) -> HashMap<String, usize> {
    let mut size_ctx = HashMap::new();
    for item in items {
        if let Ok(size) = item.measure(&mut size_ctx) {
            if !item.save.is_empty() {
                size_ctx.insert(item.save.clone(), size);
            }
        }
    }
    size_ctx
}

// --- JSON parsing ----------------------------------------------------------

#[derive(Deserialize, Default)]
struct RawRange {
    #[serde(default)]
    from: i64,
    #[serde(default)]
    to: i64,
}

#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct RawItem {
    #[serde(default)]
    delay: Option<RawRange>,
    #[serde(default)]
    rand: i64,
    #[serde(default)]
    rand_range: Option<RawRange>,
    #[serde(default)]
    capture: String,
    #[serde(default, rename = "type")]
    r#type: String,
    #[serde(default)]
    reuse: String,
    #[serde(default)]
    transform: Option<RawTransform>,
    #[serde(default)]
    packet: Option<Value>,
}

#[derive(Deserialize, Default)]
struct RawTransform {
    #[serde(default)]
    op: String,
    #[serde(default)]
    args: Vec<RawArg>,
}

#[derive(Deserialize, Default)]
struct RawArg {
    #[serde(default, rename = "type")]
    r#type: String,
    #[serde(default)]
    bytes: Option<Value>,
    #[serde(default)]
    u64: Option<u64>,
    #[serde(default)]
    reuse: String,
    #[serde(default)]
    metadata: String,
    #[serde(default)]
    transform: Option<RawTransform>,
}

fn validate_var_name(name: &str) -> bool {
    if name.is_empty() {
        return true;
    }
    let mut chars = name.chars();
    match chars.next() {
        Some(c) if c.is_ascii_alphabetic() || c == '_' => {}
        _ => return false,
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

fn validate_item_spec(item: &RawItem) -> Result<(), FinalmaskError> {
    if !validate_var_name(&item.capture) || !validate_var_name(&item.reuse) {
        return Err(invalid("invalid variable name"));
    }

    let mut kind = 0;
    if item.packet.is_some() {
        kind += 1;
    }
    if item.rand > 0 {
        kind += 1;
    }
    if !item.reuse.is_empty() {
        kind += 1;
    }
    if item.transform.is_some() {
        kind += 1;
    }
    if kind > 1 {
        return Err(invalid("exactly one item kind must be set"));
    }
    if kind == 0 && !item.capture.is_empty() {
        return Err(invalid("exactly one item kind must be set"));
    }
    Ok(())
}

fn convert_item(raw: RawItem, with_delay: bool) -> Result<Item, FinalmaskError> {
    let RawItem {
        delay,
        rand,
        rand_range,
        capture,
        r#type,
        reuse,
        transform,
        packet,
    } = raw;

    let (delay_min, delay_max) = if with_delay {
        let d = delay.unwrap_or_default();
        (d.from, d.to)
    } else {
        (0, 0)
    };

    let range = rand_range.unwrap_or(RawRange { from: 0, to: 255 });
    if range.from < 0 || range.to > 255 {
        return Err(invalid("invalid randRange"));
    }

    let packet = parse_byte_slice(&packet.unwrap_or(Value::Null), &r#type)?;
    let expr = match transform {
        Some(transform) => Some(convert_transform(transform)?),
        None => None,
    };

    Ok(Item {
        delay_min,
        delay_max,
        rand,
        rand_min: range.from as u8,
        rand_max: range.to as u8,
        packet,
        save: capture,
        var: reuse,
        expr,
    })
}

fn convert_transform(raw: RawTransform) -> Result<Expr, FinalmaskError> {
    if raw.op.is_empty() {
        return Err(invalid("transform op is required"));
    }
    if !SUPPORTED_OPS.contains(&raw.op.as_str()) {
        return Err(invalid(format!("unsupported expr op: {}", raw.op)));
    }
    if raw.args.is_empty() {
        return Err(invalid("transform args are required"));
    }
    let mut args = Vec::with_capacity(raw.args.len());
    for arg in raw.args {
        args.push(convert_arg(arg)?);
    }
    Ok(Expr { op: raw.op, args })
}

fn convert_arg(raw: RawArg) -> Result<ExprArg, FinalmaskError> {
    let RawArg {
        r#type,
        bytes,
        u64,
        reuse,
        metadata,
        transform,
    } = raw;

    let mut kind = 0;
    if bytes.is_some() {
        kind += 1;
    }
    if u64.is_some() {
        kind += 1;
    }
    if !reuse.is_empty() {
        kind += 1;
    }
    if !metadata.is_empty() {
        kind += 1;
    }
    if transform.is_some() {
        kind += 1;
    }
    if kind != 1 {
        return Err(invalid("transform arg must set exactly one value"));
    }

    if let Some(bytes) = bytes {
        return Ok(ExprArg::Bytes(parse_byte_slice(&bytes, &r#type)?));
    }
    if let Some(value) = u64 {
        return Ok(ExprArg::U64(value));
    }
    if !reuse.is_empty() {
        if !validate_var_name(&reuse) {
            return Err(invalid("invalid variable name"));
        }
        return Ok(ExprArg::Var(reuse));
    }
    if !metadata.is_empty() {
        return Ok(ExprArg::Metadata(metadata));
    }
    match transform {
        Some(transform) => Ok(ExprArg::Expr(Box::new(convert_transform(transform)?))),
        None => Err(invalid("transform arg must set exactly one value")),
    }
}

// --- TCP -------------------------------------------------------------------

#[derive(Deserialize, Default)]
struct RawTcpConfig {
    #[serde(default)]
    clients: Vec<Vec<RawItem>>,
    #[serde(default)]
    servers: Vec<Vec<RawItem>>,
    #[serde(default)]
    errors: Vec<Vec<RawItem>>,
}

struct TcpPlan {
    clients: Vec<Vec<Item>>,
    servers: Vec<Vec<Item>>,
    errors: Vec<Vec<Item>>,
}

fn convert_sequences(raw: Vec<Vec<RawItem>>) -> Result<Vec<Vec<Item>>, FinalmaskError> {
    let mut out = Vec::with_capacity(raw.len());
    for seq in raw {
        let mut items = Vec::with_capacity(seq.len());
        for item in seq {
            items.push(convert_item(item, true)?);
        }
        out.push(items);
    }
    Ok(out)
}

/// The TCP `header-custom` factory.
pub struct TcpFactory {
    plan: Arc<TcpPlan>,
}

impl TcpFactory {
    pub fn new(settings: &Value) -> Result<Self, FinalmaskError> {
        let raw: RawTcpConfig =
            serde_json::from_value(settings.clone()).map_err(|e| invalid(e.to_string()))?;
        for list in [&raw.clients, &raw.servers, &raw.errors] {
            for seq in list {
                for item in seq {
                    validate_item_spec(item)?;
                }
            }
        }
        let plan = TcpPlan {
            clients: convert_sequences(raw.clients)?,
            servers: convert_sequences(raw.servers)?,
            errors: convert_sequences(raw.errors)?,
        };
        Ok(TcpFactory {
            plan: Arc::new(plan),
        })
    }
}

impl TcpMaskFactory for TcpFactory {
    fn create(&self, role: Role) -> io::Result<Box<dyn TcpMask>> {
        Ok(Box::new(TcpMaskImpl {
            role,
            plan: self.plan.clone(),
        }))
    }
}

struct TcpMaskImpl {
    role: Role,
    plan: Arc<TcpPlan>,
}

impl TcpMask for TcpMaskImpl {
    fn wrap(self: Box<Self>, inner: AnyStream) -> io::Result<AnyStream> {
        let fut = make_handshake(inner, self.plan.clone(), self.role);
        Ok(Box::new(CustomStream {
            role: self.role,
            inner: None,
            state: Mutex::new(Handshake {
                fut: Some(fut),
                auth: false,
                err: None,
            }),
        }))
    }
}

type HandshakeFuture = Pin<Box<dyn Future<Output = (AnyStream, io::Result<()>)> + Send>>;

fn make_handshake(inner: AnyStream, plan: Arc<TcpPlan>, role: Role) -> HandshakeFuture {
    Box::pin(async move {
        let mut inner = inner;
        let result = match role {
            Role::Client => client_handshake(&mut inner, &plan).await,
            Role::Server => server_handshake(&mut inner, &plan).await,
        };
        (inner, result)
    })
}

async fn client_handshake(inner: &mut AnyStream, plan: &TcpPlan) -> io::Result<()> {
    let mut ctx = EvalContext::new();
    let mut j = 0usize;
    for i in 0..plan.clients.len() {
        write_sequence(inner, &plan.clients[i], &mut ctx).await?;
        if j < plan.servers.len() {
            read_sequence(inner, &plan.servers[j], &mut ctx).await?;
            j += 1;
        }
    }
    while j < plan.servers.len() {
        read_sequence(inner, &plan.servers[j], &mut ctx).await?;
        j += 1;
    }
    Ok(())
}

async fn server_handshake(inner: &mut AnyStream, plan: &TcpPlan) -> io::Result<()> {
    let mut ctx = EvalContext::new();
    let mut j = 0usize;
    for i in 0..plan.clients.len() {
        if let Err(err) = read_sequence(inner, &plan.clients[i], &mut ctx).await {
            if i < plan.errors.len() {
                let _ = write_sequence(inner, &plan.errors[i], &mut ctx).await;
            }
            return Err(err);
        }
        if j < plan.servers.len() {
            write_sequence(inner, &plan.servers[j], &mut ctx).await?;
            j += 1;
        }
    }
    while j < plan.servers.len() {
        write_sequence(inner, &plan.servers[j], &mut ctx).await?;
        j += 1;
    }
    Ok(())
}

async fn write_sequence(
    inner: &mut AnyStream,
    sequence: &[Item],
    ctx: &mut EvalContext,
) -> io::Result<()> {
    let mut merged: Vec<u8> = Vec::new();
    for item in sequence {
        if item.delay_max > 0 {
            if !merged.is_empty() {
                inner.write_all(&merged).await?;
                inner.flush().await?;
                merged.clear();
            }
            let ms = rand_between(item.delay_min, item.delay_max).max(0) as u64;
            tokio::time::sleep(Duration::from_millis(ms)).await;
        }
        let value = item.evaluate(ctx)?;
        merged.extend_from_slice(&value);
    }
    if !merged.is_empty() {
        inner.write_all(&merged).await?;
        inner.flush().await?;
    }
    Ok(())
}

async fn read_sequence(
    inner: &mut AnyStream,
    sequence: &[Item],
    ctx: &mut EvalContext,
) -> io::Result<()> {
    for item in sequence {
        let mut size_ctx = size_map(ctx);
        let length = item.measure(&mut size_ctx)?;
        let mut buf = vec![0u8; length];
        inner.read_exact(&mut buf).await?;

        if item.rand > 0 {
            // A random body carries no expected value.
        } else if !item.packet.is_empty() {
            if item.packet != buf {
                return Err(io_err("header packet mismatch"));
            }
        } else if !item.var.is_empty() {
            match ctx.vars.get(&item.var) {
                Some(saved) if *saved == buf => {}
                _ => return Err(io_err("header variable mismatch")),
            }
        } else if let Some(expr) = &item.expr {
            let expected = evaluate_expr(expr, ctx)?.as_bytes()?;
            if expected != buf {
                return Err(io_err("header transform mismatch"));
            }
        }

        if !item.save.is_empty() {
            ctx.vars.insert(item.save.clone(), buf);
        }
    }
    Ok(())
}

struct Handshake {
    fut: Option<HandshakeFuture>,
    auth: bool,
    err: Option<String>,
}

/// A TCP stream that runs the `header-custom` handshake lazily, on the client's
/// first write or the server's first read, and passes everything through once
/// it has succeeded.
struct CustomStream {
    role: Role,
    inner: Option<AnyStream>,
    state: Mutex<Handshake>,
}

impl CustomStream {
    fn is_authed(&self) -> bool {
        self.state.lock().auth
    }

    /// Drives the handshake to completion. `Ok` is returned only once it has
    /// succeeded; a failure is remembered and replayed.
    fn drive(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let ready = {
            let mut hs = self.state.lock();
            if let Some(fut) = hs.fut.as_mut() {
                match Future::poll(fut.as_mut(), cx) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(outcome) => Some(outcome),
                }
            } else {
                None
            }
        };
        if let Some((inner, result)) = ready {
            self.inner = Some(inner);
            let mut hs = self.state.lock();
            hs.fut = None;
            match result {
                Ok(()) => hs.auth = true,
                Err(e) => hs.err = Some(e.to_string()),
            }
        }

        let hs = self.state.lock();
        if hs.auth {
            Poll::Ready(Ok(()))
        } else if let Some(err) = &hs.err {
            Poll::Ready(Err(io_err(err)))
        } else {
            Poll::Ready(Err(io_err("header handshake did not run")))
        }
    }
}

impl AsyncRead for CustomStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.role == Role::Server {
            match this.drive(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Ready(Ok(())) => {}
            }
        } else if !this.is_authed() {
            return Poll::Ready(Err(io_err("header auth failed")));
        }
        match this.inner.as_mut() {
            Some(inner) => Pin::new(inner).poll_read(cx, buf),
            None => Poll::Ready(Err(io_err("header auth failed"))),
        }
    }
}

impl AsyncWrite for CustomStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if this.role == Role::Client {
            match this.drive(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Ready(Ok(())) => {}
            }
        } else if !this.is_authed() {
            return Poll::Ready(Err(io_err("header auth failed")));
        }
        match this.inner.as_mut() {
            Some(inner) => Pin::new(inner).poll_write(cx, buf),
            None => Poll::Ready(Err(io_err("header auth failed"))),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        match this.drive(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Ready(Ok(())) => {}
        }
        match this.inner.as_mut() {
            Some(inner) => Pin::new(inner).poll_flush(cx),
            None => Poll::Ready(Ok(())),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        match this.drive(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Ready(Ok(())) => {}
        }
        match this.inner.as_mut() {
            Some(inner) => Pin::new(inner).poll_shutdown(cx),
            None => Poll::Ready(Ok(())),
        }
    }
}

// --- UDP -------------------------------------------------------------------

#[derive(Deserialize, Default)]
struct RawUdpConfig {
    #[serde(default)]
    mode: String,
    #[serde(default)]
    client: Vec<RawItem>,
    #[serde(default)]
    server: Vec<RawItem>,
}

/// The UDP `header-custom` factory.
pub struct UdpFactory {
    client: Arc<Vec<Item>>,
    server: Arc<Vec<Item>>,
    /// The wire size of the `client` list header.
    client_size: usize,
    /// The wire size of the `server` list header, measured with the client's
    /// captured sizes as the fallback context.
    server_size: usize,
}

fn convert_udp_items(raw: Vec<RawItem>) -> Result<Vec<Item>, FinalmaskError> {
    let mut out = Vec::with_capacity(raw.len());
    for item in raw {
        out.push(convert_item(item, false)?);
    }
    Ok(out)
}

impl UdpFactory {
    pub fn new(settings: &Value) -> Result<Self, FinalmaskError> {
        let raw: RawUdpConfig =
            serde_json::from_value(settings.clone()).map_err(|e| invalid(e.to_string()))?;

        match raw.mode.as_str() {
            "" | "prefix" => {}
            "standalone" => return Err(invalid("unsupported udp mode: standalone")),
            other => return Err(invalid(format!("unknown udp mode: {}", other))),
        }

        for item in raw.client.iter().chain(raw.server.iter()) {
            validate_item_spec(item)?;
        }

        let client = convert_udp_items(raw.client)?;
        let server = convert_udp_items(raw.server)?;

        let saved = collect_saved_sizes(&client);
        let client_size = measure_items(&client, &HashMap::new()).map_err(|e| invalid(e))?;
        let server_size = measure_items(&server, &saved).map_err(|e| invalid(e))?;

        Ok(UdpFactory {
            client: Arc::new(client),
            server: Arc::new(server),
            client_size,
            server_size,
        })
    }
}

impl UdpMaskFactory for UdpFactory {
    fn create(&self, role: Role) -> io::Result<Box<dyn UdpMask>> {
        let (enc, dec, enc_size, dec_size) = match role {
            Role::Client => (
                self.client.clone(),
                self.server.clone(),
                self.client_size,
                self.server_size,
            ),
            Role::Server => (
                self.server.clone(),
                self.client.clone(),
                self.server_size,
                self.client_size,
            ),
        };
        Ok(Box::new(CustomUdpMask {
            enc,
            dec,
            enc_size,
            dec_size,
            state: Mutex::new(StateStore::new(Duration::from_secs(5))),
            last_vars: HashMap::new(),
        }))
    }
}

struct StateStore {
    ttl: Duration,
    entries: HashMap<String, (HashMap<String, Vec<u8>>, Instant)>,
}

impl StateStore {
    fn new(ttl: Duration) -> Self {
        StateStore {
            ttl,
            entries: HashMap::new(),
        }
    }

    fn get(&mut self, key: &str) -> Option<HashMap<String, Vec<u8>>> {
        let expired = matches!(self.entries.get(key), Some((_, at)) if Instant::now() > *at);
        if expired {
            self.entries.remove(key);
            return None;
        }
        self.entries.get(key).map(|(vars, _)| vars.clone())
    }

    fn set(&mut self, key: String, vars: HashMap<String, Vec<u8>>) {
        self.entries.insert(key, (vars, Instant::now() + self.ttl));
    }
}

fn state_key(meta: &PacketMeta) -> String {
    meta.remote.map(|addr| addr.to_string()).unwrap_or_default()
}

fn match_udp_items(
    items: &[Item],
    data: &[u8],
    total_size: usize,
    initial: HashMap<String, Vec<u8>>,
) -> Option<HashMap<String, Vec<u8>>> {
    if data.len() < total_size {
        return None;
    }

    let mut ctx = EvalContext {
        vars: initial,
        metadata: HashMap::new(),
    };
    let mut offset = 0usize;
    for item in items {
        let mut size_ctx = size_map(&ctx);
        let length = item.measure(&mut size_ctx).ok()?;
        if data.len().saturating_sub(offset) < length {
            return None;
        }
        let segment = &data[offset..offset + length];

        if item.rand > 0 {
            // A random body carries no expected value.
        } else if !item.packet.is_empty() {
            if item.packet != segment {
                return None;
            }
        } else if !item.var.is_empty() {
            match ctx.vars.get(&item.var) {
                Some(saved) if saved.as_slice() == segment => {}
                _ => return None,
            }
        } else if let Some(expr) = &item.expr {
            let expected = evaluate_expr(expr, &ctx).ok()?.as_bytes().ok()?;
            if expected != segment {
                return None;
            }
        }

        if !item.save.is_empty() {
            ctx.vars.insert(item.save.clone(), segment.to_vec());
        }
        offset += length;
    }
    Some(ctx.vars)
}

struct CustomUdpMask {
    enc: Arc<Vec<Item>>,
    dec: Arc<Vec<Item>>,
    enc_size: usize,
    dec_size: usize,
    state: Mutex<StateStore>,
    last_vars: HashMap<String, Vec<u8>>,
}

impl UdpMask for CustomUdpMask {
    fn encode(
        &mut self,
        pkt: &[u8],
        meta: &PacketMeta,
        out: &mut dyn FnMut(&[u8]) -> io::Result<()>,
    ) -> io::Result<()> {
        let key = state_key(meta);
        let mut ctx = EvalContext::with_meta(meta);
        if let Some(vars) = self.state.lock().get(&key) {
            ctx.vars = vars;
        } else if !self.last_vars.is_empty() {
            ctx.vars = self.last_vars.clone();
        }

        let header = match evaluate_items(&self.enc, &mut ctx) {
            Ok(header) => header,
            Err(_) => return Ok(()),
        };
        if header.len() != self.enc_size {
            return Ok(());
        }
        self.state.lock().set(key, ctx.vars.clone());

        let mut wire = Vec::with_capacity(header.len() + pkt.len());
        wire.extend_from_slice(&header);
        wire.extend_from_slice(pkt);
        out(&wire)
    }

    fn decode(&mut self, pkt: &[u8], meta: &PacketMeta) -> io::Result<Option<Vec<u8>>> {
        let key = state_key(meta);
        let initial = self.state.lock().get(&key).unwrap_or_default();
        let vars = match match_udp_items(&self.dec, pkt, self.dec_size, initial) {
            Some(vars) => vars,
            None => return Ok(None),
        };
        self.last_vars = vars.clone();
        self.state.lock().set(key, vars);
        Ok(Some(pkt[self.dec_size..].to_vec()))
    }
}
