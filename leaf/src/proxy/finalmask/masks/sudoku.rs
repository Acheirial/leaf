//! The `sudoku` mask: an appearance transform that hides payload bytes as a
//! stream of "hints" drawn from a 4x4 Sudoku grid.
//!
//! The 288 distinct 4x4 grids are generated once by DFS. Every byte value is
//! assigned one grid (a password-seeded shuffle fixes the assignment), and for
//! each grid the four positions of the four values form a 2-bit-value +
//! 4-bit-position clue group. A table maps every byte to the list of clue
//! groups that decode back to it uniquely.
//!
//! One byte becomes four hint bytes, picked from a random permutation of the
//! four hint positions, so the wire never reveals the group order. Decoding
//! collects hint bytes, sorts the four, and looks the tuple up.
//!
//! TCP uses two framings. The "pure" framing carries the four hint bytes of
//! every byte directly. The "packed" framing first packs eight payload bits
//! into 6-bit groups and encodes each group as one hint byte, so a byte costs
//! about 0.75 hint bytes instead of 4. A client writes pure and reads packed;
//! a server reads pure and writes packed (see `newPackedDirectionalConn` in
//! Xray). UDP encodes each datagram with a fresh 4-byte-per-byte codec and
//! decodes from table 0, dropping any datagram that does not decode cleanly.

use std::collections::{HashMap, HashSet};
use std::io;
use std::pin::Pin;
use std::sync::{Arc, OnceLock};
use std::task::{Context, Poll};

use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use serde_derive::Deserialize;
use serde_json::Value;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use super::{PacketMeta, Role, TcpMask, TcpMaskFactory, UdpMask, UdpMaskFactory};
use crate::proxy::finalmask::FinalmaskError;
use crate::proxy::AnyStream;

const IO_BUF: usize = 32 * 1024;
const MASK_NAME: &str = "sudoku";

fn invalid(reason: impl Into<String>) -> FinalmaskError {
    FinalmaskError::Invalid {
        mask: MASK_NAME.to_string(),
        reason: reason.into(),
    }
}

fn ioerr(err: FinalmaskError) -> io::Error {
    io::Error::other(err.to_string())
}

/// The 24 permutations of the four hint positions.
const PERM4: [[u8; 4]; 24] = [
    [0, 1, 2, 3],
    [0, 1, 3, 2],
    [0, 2, 1, 3],
    [0, 2, 3, 1],
    [0, 3, 1, 2],
    [0, 3, 2, 1],
    [1, 0, 2, 3],
    [1, 0, 3, 2],
    [1, 2, 0, 3],
    [1, 2, 3, 0],
    [1, 3, 0, 2],
    [1, 3, 2, 0],
    [2, 0, 1, 3],
    [2, 0, 3, 1],
    [2, 1, 0, 3],
    [2, 1, 3, 0],
    [2, 3, 0, 1],
    [2, 3, 1, 0],
    [3, 0, 1, 2],
    [3, 0, 2, 1],
    [3, 1, 0, 2],
    [3, 1, 2, 0],
    [3, 2, 0, 1],
    [3, 2, 1, 0],
];

// --- Settings -------------------------------------------------------------

#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct SudokuSettings {
    #[serde(default)]
    password: String,
    #[serde(default)]
    ascii: String,
    #[serde(default)]
    custom_table: String,
    #[serde(default, rename = "custom_table")]
    legacy_custom_table: String,
    #[serde(default)]
    custom_tables: Vec<String>,
    #[serde(default, rename = "custom_tables")]
    legacy_custom_sets: Vec<String>,
    #[serde(default)]
    padding_min: u32,
    #[serde(default, rename = "padding_min")]
    legacy_padding_min: u32,
    #[serde(default)]
    padding_max: u32,
    #[serde(default, rename = "padding_max")]
    legacy_padding_max: u32,
}

impl SudokuSettings {
    /// Mirrors Xray's `Sudoku.Build`: a camelCase value wins, and an explicit
    /// empty/zero falls back to the legacy snake_case key.
    fn resolve(&self) -> (String, Vec<String>, u32, u32) {
        let custom_table = if self.custom_table.is_empty() {
            self.legacy_custom_table.clone()
        } else {
            self.custom_table.clone()
        };
        let custom_tables = if self.custom_tables.is_empty() {
            self.legacy_custom_sets.clone()
        } else {
            self.custom_tables.clone()
        };
        let padding_min = if self.padding_min == 0 {
            self.legacy_padding_min
        } else {
            self.padding_min
        };
        let padding_max = if self.padding_max == 0 {
            self.legacy_padding_max
        } else {
            self.padding_max
        };
        (custom_table, custom_tables, padding_min, padding_max)
    }
}

// --- Byte layouts ---------------------------------------------------------

#[derive(Clone)]
enum LayoutKind {
    Ascii,
    Entropy,
    Custom {
        x_mask: u8,
        p_bits: [u8; 2],
        v_bits: [u8; 4],
    },
}

/// How a clue group and a single hint byte relate to the wire, plus the pool of
/// bytes that may be injected as padding.
#[derive(Clone)]
struct ByteLayout {
    kind: LayoutKind,
    hint_mask: u8,
    hint_value: u8,
    pad_marker: u8,
    padding_pool: Vec<u8>,
}

impl ByteLayout {
    fn is_hint(&self, b: u8) -> bool {
        if (b & self.hint_mask) == self.hint_value {
            return true;
        }
        // The ASCII layout maps 0x7f to '\n' to keep DEL off the wire.
        self.hint_mask == 0x40 && b == b'\n'
    }

    fn encode_group(&self, group: u8) -> u8 {
        match &self.kind {
            LayoutKind::Ascii => {
                let b = 0x40 | (group & 0x3f);
                if b == 0x7f {
                    b'\n'
                } else {
                    b
                }
            }
            LayoutKind::Entropy => {
                let v = group & 0x3f;
                ((v & 0x30) << 1) | (v & 0x0f)
            }
            LayoutKind::Custom {
                x_mask,
                p_bits,
                v_bits,
            } => custom_encode(*x_mask, &[], *p_bits, *v_bits, group, -1),
        }
    }

    fn encode_hint(&self, group: u8) -> u8 {
        self.encode_group(group)
    }

    fn decode_group(&self, b: u8) -> Option<u8> {
        match &self.kind {
            LayoutKind::Ascii => {
                if b == b'\n' {
                    return Some(0x3f);
                }
                if (b & 0x40) == 0 {
                    return None;
                }
                Some(b & 0x3f)
            }
            LayoutKind::Entropy => {
                if (b & 0x90) != 0 {
                    return None;
                }
                Some(((b >> 1) & 0x30) | (b & 0x0f))
            }
            LayoutKind::Custom {
                x_mask,
                p_bits,
                v_bits,
            } => {
                if (b & *x_mask) != *x_mask {
                    return None;
                }
                let mut val = 0u8;
                let mut pos = 0u8;
                if b & (1 << p_bits[0]) != 0 {
                    val |= 0x02;
                }
                if b & (1 << p_bits[1]) != 0 {
                    val |= 0x01;
                }
                for (i, bit) in v_bits.iter().enumerate() {
                    if b & (1 << *bit) != 0 {
                        pos |= 1 << (3 - i as u8);
                    }
                }
                Some(((val & 0x03) << 4) | (pos & 0x0f))
            }
        }
    }
}

/// Encodes one 6-bit group into a custom-pattern byte. `drop_x` drops one of
/// the two `x` bits to build the padding pool; `-1` keeps both.
fn custom_encode(
    x_mask: u8,
    x_bits: &[u8],
    p_bits: [u8; 2],
    v_bits: [u8; 4],
    group: u8,
    drop_x: i32,
) -> u8 {
    let mut out = x_mask;
    if drop_x >= 0 {
        out &= !(1u8 << x_bits[drop_x as usize]);
    }

    let val = (group >> 4) & 0x03;
    let pos = group & 0x0f;

    if val & 0x02 != 0 {
        out |= 1 << p_bits[0];
    }
    if val & 0x01 != 0 {
        out |= 1 << p_bits[1];
    }
    for (i, bit) in v_bits.iter().enumerate() {
        if (pos >> (3 - i as u8)) & 0x01 == 1 {
            out |= 1 << *bit;
        }
    }
    out
}

fn ascii_layout() -> ByteLayout {
    let mut padding = Vec::with_capacity(32);
    for i in 0..32u8 {
        padding.push(0x20 + i);
    }
    ByteLayout {
        kind: LayoutKind::Ascii,
        hint_mask: 0x40,
        hint_value: 0x40,
        pad_marker: 0x3f,
        padding_pool: padding,
    }
}

fn entropy_layout() -> ByteLayout {
    let mut padding = Vec::with_capacity(16);
    for i in 0..8u8 {
        padding.push(0x80 + i);
        padding.push(0x10 + i);
    }
    ByteLayout {
        kind: LayoutKind::Entropy,
        hint_mask: 0x90,
        hint_value: 0x00,
        pad_marker: 0x80,
        padding_pool: padding,
    }
}

fn custom_layout(pattern: &str) -> Result<ByteLayout, FinalmaskError> {
    let pattern = normalize_custom_table(pattern)?;

    let mut x_bits: Vec<u8> = Vec::new();
    let mut p_bits: Vec<u8> = Vec::new();
    let mut v_bits: Vec<u8> = Vec::new();
    for (i, c) in pattern.bytes().enumerate() {
        let bit = 7 - i as u8;
        match c {
            b'x' => x_bits.push(bit),
            b'p' => p_bits.push(bit),
            b'v' => v_bits.push(bit),
            _ => {}
        }
    }

    let mut x_mask = 0u8;
    for bit in &x_bits {
        x_mask |= 1 << *bit;
    }
    let p_bits: [u8; 2] = p_bits.try_into().unwrap();
    let v_bits: [u8; 4] = v_bits.try_into().unwrap();

    let mut seen: HashSet<u8> = HashSet::new();
    let mut padding: Vec<u8> = Vec::new();
    for drop in 0..x_bits.len() {
        for val in 0u8..4 {
            for pos in 0u8..16 {
                let group = (val << 4) | pos;
                let b = custom_encode(x_mask, &x_bits, p_bits, v_bits, group, drop as i32);
                if b.count_ones() >= 5 && seen.insert(b) {
                    padding.push(b);
                }
            }
        }
    }
    padding.sort_unstable();
    if padding.is_empty() {
        return Err(invalid("customTable produced empty padding pool"));
    }
    let pad_marker = padding[0];

    Ok(ByteLayout {
        kind: LayoutKind::Custom {
            x_mask,
            p_bits,
            v_bits,
        },
        hint_mask: x_mask,
        hint_value: x_mask,
        pad_marker,
        padding_pool: padding,
    })
}

// --- Table derivation -----------------------------------------------------

fn sort4(mut c: [u8; 4]) -> [u8; 4] {
    if c[0] > c[1] {
        c.swap(0, 1);
    }
    if c[2] > c[3] {
        c.swap(2, 3);
    }
    if c[0] > c[2] {
        c.swap(0, 2);
    }
    if c[1] > c[3] {
        c.swap(1, 3);
    }
    if c[1] > c[2] {
        c.swap(1, 2);
    }
    c
}

fn pack_key(c: [u8; 4]) -> u32 {
    (c[0] as u32) << 24 | (c[1] as u32) << 16 | (c[2] as u32) << 8 | c[3] as u32
}

fn clue_group(g: &[u8; 16], pos: u8) -> u8 {
    ((g[pos as usize] - 1) << 4) | (pos & 0x0f)
}

fn generate_all_grids() -> Vec<[u8; 16]> {
    fn dfs(idx: usize, g: &mut [u8; 16], grids: &mut Vec<[u8; 16]>) {
        if idx == 16 {
            grids.push(*g);
            return;
        }
        let row = idx / 4;
        let col = idx % 4;
        let box_row = (row / 2) * 2;
        let box_col = (col / 2) * 2;

        for num in 1..=4u8 {
            let mut valid = true;
            for i in 0..4 {
                if g[row * 4 + i] == num || g[i * 4 + col] == num {
                    valid = false;
                    break;
                }
            }
            if !valid {
                continue;
            }
            'boxes: for r in 0..2 {
                for c in 0..2 {
                    if g[(box_row + r) * 4 + (box_col + c)] == num {
                        valid = false;
                        break 'boxes;
                    }
                }
            }
            if !valid {
                continue;
            }

            g[idx] = num;
            dfs(idx + 1, g, grids);
            g[idx] = 0;
        }
    }

    let mut grids = Vec::with_capacity(288);
    let mut g = [0u8; 16];
    dfs(0, &mut g, &mut grids);
    grids
}

fn hint_positions() -> Vec<[u8; 4]> {
    let mut positions = Vec::with_capacity(1820);
    for a in 0..13u8 {
        for b in (a + 1)..14 {
            for c in (b + 1)..15 {
                for d in (c + 1)..16 {
                    positions.push([a, b, c, d]);
                }
            }
        }
    }
    positions
}

type PatternList = Vec<[u8; 4]>;

fn build_base_patterns() -> Vec<PatternList> {
    let grids = generate_all_grids();
    let positions = hint_positions();

    let mut patterns: Vec<PatternList> = (0..grids.len()).map(|_| Vec::new()).collect();

    for ps in &positions {
        let mut counts: HashMap<u32, u16> = HashMap::with_capacity(grids.len());
        let mut keys: Vec<u32> = Vec::with_capacity(grids.len());
        let mut groups_by_grid: Vec<[u8; 4]> = Vec::with_capacity(grids.len());

        for g in &grids {
            let mut groups = [0u8; 4];
            for (k, pos) in ps.iter().enumerate() {
                groups[k] = clue_group(g, *pos);
            }
            let groups = sort4(groups);
            let key = pack_key(groups);
            keys.push(key);
            groups_by_grid.push(groups);
            *counts.entry(key).or_insert(0) += 1;
        }

        for (gi, key) in keys.iter().enumerate() {
            if counts[key] == 1 {
                patterns[gi].push(groups_by_grid[gi]);
            }
        }
    }

    patterns
}

fn base_patterns() -> &'static [PatternList] {
    static BASE_PATTERNS: OnceLock<Vec<PatternList>> = OnceLock::new();
    BASE_PATTERNS.get_or_init(build_base_patterns).as_slice()
}

/// One byte's decode table plus the layouts used to paint it on the wire.
struct Table {
    encode: [Vec<[u8; 4]>; 256],
    decode: HashMap<u32, u8>,
    layout: Arc<ByteLayout>,
}

fn build_table(password: &str, layout: Arc<ByteLayout>) -> Result<Table, FinalmaskError> {
    let patterns = base_patterns();
    if patterns.len() < 256 {
        return Err(invalid(format!(
            "not enough sudoku grids: {}",
            patterns.len()
        )));
    }

    let mut order: Vec<usize> = (0..patterns.len()).collect();
    let digest = sha256(password.as_bytes());
    let seed = i64::from_be_bytes(digest[0..8].try_into().unwrap());
    let mut rng = RngSource::new(seed);
    rng.shuffle(&mut order);

    let mut encode: [Vec<[u8; 4]>; 256] = std::array::from_fn(|_| Vec::new());
    let mut decode: HashMap<u32, u8> = HashMap::with_capacity(1 << 16);

    for b in 0..256usize {
        let pat_list = &patterns[order[b]];
        if pat_list.is_empty() {
            return Err(invalid(format!("grid {} has no valid clue set", order[b])));
        }

        let mut enc: Vec<[u8; 4]> = Vec::with_capacity(pat_list.len());
        for groups in pat_list {
            let hints = [
                layout.encode_hint(groups[0]),
                layout.encode_hint(groups[1]),
                layout.encode_hint(groups[2]),
                layout.encode_hint(groups[3]),
            ];
            let key = pack_key(sort4(hints));
            if let Some(&old) = decode.get(&key) {
                if old != b as u8 {
                    return Err(invalid(format!(
                        "decode key collision for byte {} and {}",
                        old, b
                    )));
                }
            }
            decode.insert(key, b as u8);
            enc.push(hints);
        }
        encode[b] = enc;
    }

    Ok(Table {
        encode,
        decode,
        layout,
    })
}

// --- Settings normalization ----------------------------------------------

fn normalize_ascii(mode: &str) -> Result<String, FinalmaskError> {
    match mode.trim().to_lowercase().as_str() {
        "" | "entropy" | "prefer_entropy" => Ok("prefer_entropy".to_string()),
        "ascii" | "prefer_ascii" => Ok("prefer_ascii".to_string()),
        other => Err(invalid(format!("invalid sudoku ascii mode: {}", other))),
    }
}

fn normalize_custom_table(pattern: &str) -> Result<String, FinalmaskError> {
    let cleaned: String = pattern
        .trim()
        .to_lowercase()
        .chars()
        .filter(|c| *c != ' ')
        .collect();
    if cleaned.len() != 8 {
        return Err(invalid(format!(
            "customTable must be 8 chars, got {}",
            cleaned.len()
        )));
    }

    let mut x_count = 0;
    let mut p_count = 0;
    let mut v_count = 0;
    for c in cleaned.chars() {
        match c {
            'x' => x_count += 1,
            'p' => p_count += 1,
            'v' => v_count += 1,
            other => {
                return Err(invalid(format!("customTable has invalid char {:?}", other)));
            }
        }
    }
    if x_count != 2 || p_count != 2 || v_count != 4 {
        return Err(invalid("customTable must contain exactly 2 x, 2 p and 4 v"));
    }
    Ok(cleaned)
}

fn normalized_custom_patterns(
    custom_table: &str,
    custom_tables: &[String],
    mode: &str,
) -> Result<Vec<String>, FinalmaskError> {
    if mode == "prefer_ascii" {
        return Ok(vec![String::new()]);
    }

    let raw_patterns: Vec<&str> = if !custom_tables.is_empty() {
        custom_tables.iter().map(|s| s.as_str()).collect()
    } else {
        vec![custom_table]
    };

    let mut patterns: Vec<String> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();
    for raw in raw_patterns {
        let trimmed = raw.trim();
        let pattern = if trimmed.is_empty() {
            String::new()
        } else {
            normalize_custom_table(trimmed)?
        };
        if seen.insert(pattern.clone()) {
            patterns.push(pattern);
        }
    }

    if patterns.is_empty() {
        patterns.push(String::new());
    }
    Ok(patterns)
}

fn resolve_layout(mode: &str, custom_table: &str) -> Result<ByteLayout, FinalmaskError> {
    if mode == "prefer_ascii" {
        return Ok(ascii_layout());
    }
    if !custom_table.is_empty() {
        return custom_layout(custom_table);
    }
    Ok(entropy_layout())
}

fn normalized_padding(mut p_min: i64, mut p_max: i64) -> (i64, i64) {
    if p_min > 100 {
        p_min = 100;
    }
    if p_max > 100 {
        p_max = 100;
    }
    if p_max < p_min {
        p_max = p_min;
    }
    (p_min, p_max)
}

type Tables = Arc<Vec<Arc<Table>>>;

fn build_tables(settings: &Value) -> Result<(Tables, i64, i64), FinalmaskError> {
    let raw: SudokuSettings =
        serde_json::from_value(settings.clone()).map_err(|e| invalid(e.to_string()))?;

    let (custom_table, custom_tables, padding_min, padding_max) = raw.resolve();
    let mode = normalize_ascii(&raw.ascii)?;
    let patterns = normalized_custom_patterns(&custom_table, &custom_tables, &mode)?;

    let mut tables: Vec<Arc<Table>> = Vec::with_capacity(patterns.len());
    for pattern in &patterns {
        let layout = Arc::new(resolve_layout(&mode, pattern)?);
        tables.push(Arc::new(build_table(&raw.password, layout)?));
    }
    if tables.is_empty() {
        return Err(invalid("empty sudoku table set"));
    }

    let (p_min, p_max) = normalized_padding(padding_min as i64, padding_max as i64);
    Ok((Arc::new(tables), p_min, p_max))
}

// --- Runtime codec --------------------------------------------------------

/// Holds the per-connection random state used to pick permutations and insert
/// padding, plus the (single or multi-table) set to encode from.
struct Codec {
    tables: Tables,
    rng: StdRng,
    padding_chance: i32,
    table_index: usize,
}

impl Codec {
    fn new(tables: Tables, p_min: i64, p_max: i64) -> Self {
        let mut rng = StdRng::from_entropy();
        let padding_chance = pick_padding_chance(&mut rng, p_min, p_max);
        Codec {
            tables,
            rng,
            padding_chance,
            table_index: 0,
        }
    }

    fn encode(&mut self, input: &[u8]) -> Result<Vec<u8>, FinalmaskError> {
        if input.is_empty() {
            return Ok(Vec::new());
        }

        let mut out = Vec::with_capacity(input.len() * 6 + 8);
        for &b in input {
            if self.tables.is_empty() {
                return Err(invalid("sudoku table set missing"));
            }
            let table = &self.tables[self.table_index % self.tables.len()];

            if should_pad(&mut self.rng, self.padding_chance) {
                out.push(random_padding(&mut self.rng, &table.layout.padding_pool));
            }

            let enc = &table.encode[b as usize];
            if enc.is_empty() {
                return Err(invalid(format!(
                    "sudoku encode table missing for byte {}",
                    b
                )));
            }
            let hints = enc[self.rng.gen_range(0..enc.len())];
            let perm = PERM4[self.rng.gen_range(0..PERM4.len())];
            for idx in perm {
                if should_pad(&mut self.rng, self.padding_chance) {
                    out.push(random_padding(&mut self.rng, &table.layout.padding_pool));
                }
                out.push(hints[idx as usize]);
            }
            self.table_index += 1;
        }

        if should_pad(&mut self.rng, self.padding_chance) && !self.tables.is_empty() {
            let table = &self.tables[self.table_index % self.tables.len()];
            out.push(random_padding(&mut self.rng, &table.layout.padding_pool));
        }

        Ok(out)
    }
}

/// A coin flip that inserts one padding byte, matching Go's `codec.shouldPad`.
fn should_pad(rng: &mut StdRng, chance: i32) -> bool {
    if chance <= 0 {
        return false;
    }
    if chance >= 100 {
        return true;
    }
    rng.gen_range(0..100i32) < chance
}

fn pick_padding_chance(rng: &mut StdRng, mut p_min: i64, mut p_max: i64) -> i32 {
    if p_min < 0 {
        p_min = 0;
    }
    if p_max < p_min {
        p_max = p_min;
    }
    if p_min > 100 {
        p_min = 100;
    }
    if p_max > 100 {
        p_max = 100;
    }
    if p_max == p_min {
        return p_min as i32;
    }
    (p_min + rng.gen_range(0..(p_max - p_min + 1))) as i32
}

fn random_padding(rng: &mut StdRng, pool: &[u8]) -> u8 {
    pool[rng.gen_range(0..pool.len())]
}

fn decode_bytes(
    tables: &[Arc<Table>],
    table_index: &mut usize,
    input: &[u8],
    hint_buf: &mut Vec<u8>,
    out: &mut Vec<u8>,
) -> Result<(), FinalmaskError> {
    if tables.is_empty() {
        return Err(invalid("sudoku table set missing"));
    }
    for &b in input {
        let table = &tables[*table_index % tables.len()];
        if !table.layout.is_hint(b) {
            continue;
        }

        hint_buf.push(b);
        if hint_buf.len() < 4 {
            continue;
        }

        let key = pack_key(sort4([hint_buf[0], hint_buf[1], hint_buf[2], hint_buf[3]]));
        match table.decode.get(&key) {
            Some(&decoded) => {
                out.push(decoded);
                hint_buf.clear();
                *table_index += 1;
            }
            None => return Err(invalid("invalid sudoku hint tuple")),
        }
    }
    Ok(())
}

/// The packed framing packs eight payload bits into 6-bit groups and paints
/// each group as a single hint byte.
struct PackedEncoder {
    layouts: Vec<Arc<ByteLayout>>,
    codec: Codec,
    group_index: usize,
}

impl PackedEncoder {
    fn new(tables: &[Arc<Table>], p_min: i64, p_max: i64) -> Self {
        let mut layouts: Vec<Arc<ByteLayout>> = tables.iter().map(|t| t.layout.clone()).collect();
        if layouts.is_empty() {
            layouts.push(Arc::new(entropy_layout()));
        }
        PackedEncoder {
            layouts,
            codec: Codec::new(Arc::new(Vec::new()), p_min, p_max),
            group_index: 0,
        }
    }

    fn encode(&mut self, input: &[u8]) -> Result<Vec<u8>, FinalmaskError> {
        let mut out = Vec::with_capacity(input.len() * 2 + 8);
        let mut bit_buf: u64 = 0;
        let mut bit_count: u32 = 0;

        for &b in input {
            bit_buf = (bit_buf << 8) | b as u64;
            bit_count += 8;

            while bit_count >= 6 {
                bit_count -= 6;
                let idx = self.group_index % self.layouts.len();
                let group = (bit_buf >> bit_count) as u8;
                packed_padding(&mut self.codec, &mut out, &self.layouts[idx]);
                out.push(self.layouts[idx].encode_group(group & 0x3f));
                self.group_index += 1;
                if bit_count > 0 {
                    bit_buf &= (1u64 << bit_count) - 1;
                } else {
                    bit_buf = 0;
                }
            }
        }

        if bit_count > 0 {
            let idx = self.group_index % self.layouts.len();
            let group = (bit_buf << (6 - bit_count)) as u8;
            packed_padding(&mut self.codec, &mut out, &self.layouts[idx]);
            out.push(self.layouts[idx].encode_group(group & 0x3f));
            self.group_index += 1;
            let next = self.group_index % self.layouts.len();
            out.push(self.layouts[next].pad_marker);
        }

        let idx = self.group_index % self.layouts.len();
        packed_padding(&mut self.codec, &mut out, &self.layouts[idx]);
        Ok(out)
    }
}

/// The packed framing's padding pick: never emits the layout's marker byte.
fn packed_padding(codec: &mut Codec, out: &mut Vec<u8>, layout: &ByteLayout) {
    if !should_pad(&mut codec.rng, codec.padding_chance) {
        return;
    }
    if layout.padding_pool.len() == 1 {
        out.push(layout.padding_pool[0]);
        return;
    }
    loop {
        let b = layout.padding_pool[codec.rng.gen_range(0..layout.padding_pool.len())];
        if b != layout.pad_marker {
            out.push(b);
            return;
        }
    }
}

struct PackedDecoder {
    layouts: Vec<Arc<ByteLayout>>,
    group_index: usize,
    bit_buf: u64,
    bit_count: u32,
}

impl PackedDecoder {
    fn new(tables: &[Arc<Table>]) -> Self {
        let mut layouts: Vec<Arc<ByteLayout>> = tables.iter().map(|t| t.layout.clone()).collect();
        if layouts.is_empty() {
            layouts.push(Arc::new(entropy_layout()));
        }
        PackedDecoder {
            layouts,
            group_index: 0,
            bit_buf: 0,
            bit_count: 0,
        }
    }

    fn decode_chunk(&mut self, input: &[u8], out: &mut Vec<u8>) -> Result<(), FinalmaskError> {
        if self.layouts.is_empty() {
            return Err(invalid("sudoku layout set missing"));
        }
        for &b in input {
            let idx = self.group_index % self.layouts.len();
            if !self.layouts[idx].is_hint(b) {
                if b == self.layouts[idx].pad_marker {
                    self.bit_buf = 0;
                    self.bit_count = 0;
                }
                continue;
            }

            let group = match self.layouts[idx].decode_group(b) {
                Some(group) => group,
                None => return Err(invalid(format!("invalid packed sudoku byte: {}", b))),
            };
            self.group_index += 1;

            self.bit_buf = (self.bit_buf << 6) | group as u64;
            self.bit_count += 6;

            while self.bit_count >= 8 {
                self.bit_count -= 8;
                out.push((self.bit_buf >> self.bit_count) as u8);
                if self.bit_count > 0 {
                    self.bit_buf &= (1u64 << self.bit_count) - 1;
                } else {
                    self.bit_buf = 0;
                }
            }
        }
        Ok(())
    }
}

// --- Stream ---------------------------------------------------------------

enum Decoder {
    Pure {
        tables: Tables,
        table_index: usize,
        hint_buf: Vec<u8>,
    },
    Packed(PackedDecoder),
}

impl Decoder {
    fn decode_chunk(&mut self, input: &[u8], out: &mut Vec<u8>) -> Result<(), FinalmaskError> {
        match self {
            Decoder::Pure {
                tables,
                table_index,
                hint_buf,
            } => decode_bytes(tables.as_slice(), table_index, input, hint_buf, out),
            Decoder::Packed(decoder) => decoder.decode_chunk(input, out),
        }
    }
}

enum Encoder {
    Pure(Codec),
    Packed(PackedEncoder),
}

impl Encoder {
    fn encode(&mut self, input: &[u8]) -> Result<Vec<u8>, FinalmaskError> {
        match self {
            Encoder::Pure(codec) => codec.encode(input),
            Encoder::Packed(packed) => packed.encode(input),
        }
    }
}

struct SudokuStream {
    inner: AnyStream,
    decoder: Decoder,
    encoder: Encoder,
    raw: Vec<u8>,
    pending: Vec<u8>,
    pending_pos: usize,
    write_pending: Vec<u8>,
    write_pos: usize,
    accepted: usize,
    active: bool,
}

impl SudokuStream {
    fn poll_drain_write(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while self.write_pos < self.write_pending.len() {
            match Pin::new(&mut self.inner).poll_write(cx, &self.write_pending[self.write_pos..]) {
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(io::Error::other("sudoku: write returned zero bytes")))
                }
                Poll::Ready(Ok(n)) => self.write_pos += n,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
        Poll::Ready(Ok(()))
    }

    fn finish_write(&mut self) -> usize {
        let n = self.accepted;
        self.accepted = 0;
        self.write_pending.clear();
        self.write_pos = 0;
        self.active = false;
        n
    }
}

impl AsyncRead for SudokuStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.as_mut().get_mut();
        loop {
            if this.pending_pos < this.pending.len() {
                let n = std::cmp::min(buf.remaining(), this.pending.len() - this.pending_pos);
                let end = this.pending_pos + n;
                buf.put_slice(&this.pending[this.pending_pos..end]);
                this.pending_pos = end;
                if this.pending_pos >= this.pending.len() {
                    this.pending.clear();
                    this.pending_pos = 0;
                }
                return Poll::Ready(Ok(()));
            }
            this.pending.clear();
            this.pending_pos = 0;

            let filled = {
                let mut read_buf = ReadBuf::new(&mut this.raw);
                match Pin::new(&mut this.inner).poll_read(cx, &mut read_buf) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Ready(Ok(())) => read_buf.filled().len(),
                }
            };
            if filled == 0 {
                return Poll::Ready(Ok(()));
            }

            if let Err(e) = this
                .decoder
                .decode_chunk(&this.raw[..filled], &mut this.pending)
            {
                return Poll::Ready(Err(ioerr(e)));
            }
        }
    }
}

impl AsyncWrite for SudokuStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.as_mut().get_mut();
        if !this.active {
            let encoded = match this.encoder.encode(buf) {
                Ok(encoded) => encoded,
                Err(e) => return Poll::Ready(Err(ioerr(e))),
            };
            this.write_pending = encoded;
            this.write_pos = 0;
            this.accepted = buf.len();
            this.active = true;
        }

        match this.poll_drain_write(cx) {
            Poll::Ready(Ok(())) => {
                let n = this.finish_write();
                Poll::Ready(Ok(n))
            }
            Poll::Ready(Err(e)) => {
                this.finish_write();
                Poll::Ready(Err(e))
            }
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.as_mut().get_mut();
        if this.active {
            match this.poll_drain_write(cx) {
                Poll::Ready(Ok(())) => {
                    this.finish_write();
                }
                Poll::Ready(Err(e)) => {
                    this.finish_write();
                    return Poll::Ready(Err(e));
                }
                Poll::Pending => return Poll::Pending,
            }
        }
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.as_mut().get_mut();
        if this.active {
            match this.poll_drain_write(cx) {
                Poll::Ready(Ok(())) => {
                    this.finish_write();
                }
                Poll::Ready(Err(e)) => {
                    this.finish_write();
                    return Poll::Ready(Err(e));
                }
                Poll::Pending => return Poll::Pending,
            }
        }
        Pin::new(&mut this.inner).poll_shutdown(cx)
    }
}

// --- Factories ------------------------------------------------------------

pub struct TcpFactory {
    tables: Tables,
    p_min: i64,
    p_max: i64,
}

impl TcpFactory {
    pub fn new(settings: &Value) -> Result<Self, FinalmaskError> {
        let (tables, p_min, p_max) = build_tables(settings)?;
        Ok(TcpFactory {
            tables,
            p_min,
            p_max,
        })
    }
}

impl TcpMaskFactory for TcpFactory {
    fn create(&self, role: Role) -> io::Result<Box<dyn TcpMask>> {
        Ok(Box::new(TcpMaskImpl {
            tables: self.tables.clone(),
            p_min: self.p_min,
            p_max: self.p_max,
            role,
        }))
    }
}

struct TcpMaskImpl {
    tables: Tables,
    p_min: i64,
    p_max: i64,
    role: Role,
}

impl TcpMask for TcpMaskImpl {
    fn wrap(self: Box<Self>, inner: AnyStream) -> io::Result<AnyStream> {
        let (encoder, decoder) = match self.role {
            // The client writes pure hints and reads the packed downlink.
            Role::Client => (
                Encoder::Pure(Codec::new(self.tables.clone(), self.p_min, self.p_max)),
                Decoder::Packed(PackedDecoder::new(self.tables.as_slice())),
            ),
            // The server reads pure hints and writes the packed downlink.
            Role::Server => (
                Encoder::Packed(PackedEncoder::new(
                    self.tables.as_slice(),
                    self.p_min,
                    self.p_max,
                )),
                Decoder::Pure {
                    tables: self.tables.clone(),
                    table_index: 0,
                    hint_buf: Vec::with_capacity(4),
                },
            ),
        };

        Ok(Box::new(SudokuStream {
            inner,
            decoder,
            encoder,
            raw: vec![0u8; IO_BUF],
            pending: Vec::new(),
            pending_pos: 0,
            write_pending: Vec::new(),
            write_pos: 0,
            accepted: 0,
            active: false,
        }))
    }
}

pub struct UdpFactory {
    tables: Tables,
    p_min: i64,
    p_max: i64,
}

impl UdpFactory {
    pub fn new(settings: &Value) -> Result<Self, FinalmaskError> {
        let (tables, p_min, p_max) = build_tables(settings)?;
        Ok(UdpFactory {
            tables,
            p_min,
            p_max,
        })
    }
}

impl UdpMaskFactory for UdpFactory {
    fn create(&self, _role: Role) -> io::Result<Box<dyn UdpMask>> {
        Ok(Box::new(UdpMaskImpl {
            tables: self.tables.clone(),
            p_min: self.p_min,
            p_max: self.p_max,
        }))
    }
}

struct UdpMaskImpl {
    tables: Tables,
    p_min: i64,
    p_max: i64,
}

impl UdpMask for UdpMaskImpl {
    fn encode(
        &mut self,
        pkt: &[u8],
        _meta: &PacketMeta,
        out: &mut dyn FnMut(&[u8]) -> io::Result<()>,
    ) -> io::Result<()> {
        // UDP decoding restarts at table 0 for every datagram, so encoding must
        // use a fresh codec too.
        let mut codec = Codec::new(self.tables.clone(), self.p_min, self.p_max);
        match codec.encode(pkt) {
            Ok(wire) => out(&wire),
            Err(_) => Ok(()),
        }
    }

    fn decode(&mut self, pkt: &[u8], _meta: &PacketMeta) -> io::Result<Option<Vec<u8>>> {
        let mut decoded = Vec::new();
        let mut hints: Vec<u8> = Vec::with_capacity(4);
        let mut table_index = 0usize;
        match decode_bytes(
            self.tables.as_slice(),
            &mut table_index,
            pkt,
            &mut hints,
            &mut decoded,
        ) {
            Ok(()) if hints.is_empty() => Ok(Some(decoded)),
            // A datagram that does not decode cleanly is dropped.
            _ => Ok(None),
        }
    }
}

// --- Password seed: SHA-256 ----------------------------------------------

fn sha256(data: &[u8]) -> [u8; 32] {
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];

    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];

    let mut msg: Vec<u8> = Vec::with_capacity(data.len() + 72);
    msg.extend_from_slice(data);
    let bit_len = (data.len() as u64).wrapping_mul(8);
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bit_len.to_be_bytes());

    for chunk in msg.chunks_exact(64) {
        let mut w = [0u32; 64];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([
                chunk[i * 4],
                chunk[i * 4 + 1],
                chunk[i * 4 + 2],
                chunk[i * 4 + 3],
            ]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }

        let mut a = h[0];
        let mut b = h[1];
        let mut c = h[2];
        let mut d = h[3];
        let mut e = h[4];
        let mut f = h[5];
        let mut g = h[6];
        let mut hh = h[7];

        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let t1 = hh
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(maj);

            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }

        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
        h[5] = h[5].wrapping_add(f);
        h[6] = h[6].wrapping_add(g);
        h[7] = h[7].wrapping_add(hh);
    }

    let mut out = [0u8; 32];
    for (i, word) in h.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
    }
    out
}

// --- Password seed: Go's math/rand (rngSource) ---------------------------
//
// `getTables` seeds `rand.New(rand.NewSource(seed))` with the leading eight
// bytes of the SHA-256 of the password and uses `Shuffle` over the grid order.
// The generator is Go's 607-word lagged-Fibonacci source; the port below is
// bit-exact so a Rust peer derives the same tables as a Go peer.

const RNG_LEN: i32 = 607;
const RNG_TAP: i32 = 273;
const INT32MAX: i32 = (1 << 31) - 1;

/// `rngCooked` from Go's `math/rand/rng.go`.
const RNG_COOKED: [i64; 607] = [
    -4181792142133755926,
    -4576982950128230565,
    1395769623340756751,
    5333664234075297259,
    -6347679516498800754,
    9033628115061424579,
    7143218595135194537,
    4812947590706362721,
    7937252194349799378,
    5307299880338848416,
    8209348851763925077,
    -7107630437535961764,
    4593015457530856296,
    8140875735541888011,
    -5903942795589686782,
    -603556388664454774,
    -7496297993371156308,
    113108499721038619,
    4569519971459345583,
    -4160538177779461077,
    -6835753265595711384,
    -6507240692498089696,
    6559392774825876886,
    7650093201692370310,
    7684323884043752161,
    -8965504200858744418,
    -2629915517445760644,
    271327514973697897,
    -6433985589514657524,
    1065192797246149621,
    3344507881999356393,
    -4763574095074709175,
    7465081662728599889,
    1014950805555097187,
    -4773931307508785033,
    -5742262670416273165,
    2418672789110888383,
    5796562887576294778,
    4484266064449540171,
    3738982361971787048,
    -4699774852342421385,
    10530508058128498,
    -589538253572429690,
    -6598062107225984180,
    8660405965245884302,
    10162832508971942,
    -2682657355892958417,
    7031802312784620857,
    6240911277345944669,
    831864355460801054,
    -1218937899312622917,
    2116287251661052151,
    2202309800992166967,
    9161020366945053561,
    4069299552407763864,
    4936383537992622449,
    457351505131524928,
    -8881176990926596454,
    -6375600354038175299,
    -7155351920868399290,
    4368649989588021065,
    887231587095185257,
    -3659780529968199312,
    -2407146836602825512,
    5616972787034086048,
    -751562733459939242,
    1686575021641186857,
    -5177887698780513806,
    -4979215821652996885,
    -1375154703071198421,
    5632136521049761902,
    -8390088894796940536,
    -193645528485698615,
    -5979788902190688516,
    -4907000935050298721,
    -285522056888777828,
    -2776431630044341707,
    1679342092332374735,
    6050638460742422078,
    -2229851317345194226,
    -1582494184340482199,
    5881353426285907985,
    812786550756860885,
    4541845584483343330,
    -6497901820577766722,
    4980675660146853729,
    -4012602956251539747,
    -329088717864244987,
    -2896929232104691526,
    1495812843684243920,
    -2153620458055647789,
    7370257291860230865,
    -2466442761497833547,
    4706794511633873654,
    -1398851569026877145,
    8549875090542453214,
    -9189721207376179652,
    -7894453601103453165,
    7297902601803624459,
    1011190183918857495,
    -6985347000036920864,
    5147159997473910359,
    -8326859945294252826,
    2659470849286379941,
    6097729358393448602,
    -7491646050550022124,
    -5117116194870963097,
    -896216826133240300,
    -745860416168701406,
    5803876044675762232,
    -787954255994554146,
    -3234519180203704564,
    -4507534739750823898,
    -1657200065590290694,
    505808562678895611,
    -4153273856159712438,
    -8381261370078904295,
    572156825025677802,
    1791881013492340891,
    3393267094866038768,
    -5444650186382539299,
    2352769483186201278,
    -7930912453007408350,
    -325464993179687389,
    -3441562999710612272,
    -6489413242825283295,
    5092019688680754699,
    -227247482082248967,
    4234737173186232084,
    5027558287275472836,
    4635198586344772304,
    -536033143587636457,
    5907508150730407386,
    -8438615781380831356,
    972392927514829904,
    -3801314342046600696,
    -4064951393885491917,
    -174840358296132583,
    2407211146698877100,
    -1640089820333676239,
    3940796514530962282,
    -5882197405809569433,
    3095313889586102949,
    -1818050141166537098,
    5832080132947175283,
    7890064875145919662,
    8184139210799583195,
    -8073512175445549678,
    -7758774793014564506,
    -4581724029666783935,
    3516491885471466898,
    -8267083515063118116,
    6657089965014657519,
    5220884358887979358,
    1796677326474620641,
    5340761970648932916,
    1147977171614181568,
    5066037465548252321,
    2574765911837859848,
    1085848279845204775,
    -5873264506986385449,
    6116438694366558490,
    2107701075971293812,
    -7420077970933506541,
    2469478054175558874,
    -1855128755834809824,
    -5431463669011098282,
    -9038325065738319171,
    -6966276280341336160,
    7217693971077460129,
    -8314322083775271549,
    7196649268545224266,
    -3585711691453906209,
    -5267827091426810625,
    8057528650917418961,
    -5084103596553648165,
    -2601445448341207749,
    -7850010900052094367,
    6527366231383600011,
    3507654575162700890,
    9202058512774729859,
    1954818376891585542,
    -2582991129724600103,
    8299563319178235687,
    -5321504681635821435,
    7046310742295574065,
    -2376176645520785576,
    -7650733936335907755,
    8850422670118399721,
    3631909142291992901,
    5158881091950831288,
    -6340413719511654215,
    4763258931815816403,
    6280052734341785344,
    -4979582628649810958,
    2043464728020827976,
    -2678071570832690343,
    4562580375758598164,
    5495451168795427352,
    -7485059175264624713,
    553004618757816492,
    6895160632757959823,
    -989748114590090637,
    7139506338801360852,
    -672480814466784139,
    5535668688139305547,
    2430933853350256242,
    -3821430778991574732,
    -1063731997747047009,
    -3065878205254005442,
    7632066283658143750,
    6308328381617103346,
    3681878764086140361,
    3289686137190109749,
    6587997200611086848,
    244714774258135476,
    -5143583659437639708,
    8090302575944624335,
    2945117363431356361,
    -8359047641006034763,
    3009039260312620700,
    -793344576772241777,
    401084700045993341,
    -1968749590416080887,
    4707864159563588614,
    -3583123505891281857,
    -3240864324164777915,
    -5908273794572565703,
    -3719524458082857382,
    -5281400669679581926,
    8118566580304798074,
    3839261274019871296,
    7062410411742090847,
    -8481991033874568140,
    6027994129690250817,
    -6725542042704711878,
    -2971981702428546974,
    -7854441788951256975,
    8809096399316380241,
    6492004350391900708,
    2462145737463489636,
    -8818543617934476634,
    -5070345602623085213,
    -8961586321599299868,
    -3758656652254704451,
    -8630661632476012791,
    6764129236657751224,
    -709716318315418359,
    -3403028373052861600,
    -8838073512170985897,
    -3999237033416576341,
    -2920240395515973663,
    -2073249475545404416,
    368107899140673753,
    -6108185202296464250,
    -6307735683270494757,
    4782583894627718279,
    6718292300699989587,
    8387085186914375220,
    3387513132024756289,
    4654329375432538231,
    -292704475491394206,
    -3848998599978456535,
    7623042350483453954,
    7725442901813263321,
    9186225467561587250,
    -5132344747257272453,
    -6865740430362196008,
    2530936820058611833,
    1636551876240043639,
    -3658707362519810009,
    1452244145334316253,
    -7161729655835084979,
    -7943791770359481772,
    9108481583171221009,
    -3200093350120725999,
    5007630032676973346,
    2153168792952589781,
    6720334534964750538,
    -3181825545719981703,
    3433922409283786309,
    2285479922797300912,
    3110614940896576130,
    -2856812446131932915,
    -3804580617188639299,
    7163298419643543757,
    4891138053923696990,
    580618510277907015,
    1684034065251686769,
    4429514767357295841,
    -8893025458299325803,
    -8103734041042601133,
    7177515271653460134,
    4589042248470800257,
    -1530083407795771245,
    143607045258444228,
    246994305896273627,
    -8356954712051676521,
    6473547110565816071,
    3092379936208876896,
    2058427839513754051,
    -4089587328327907870,
    8785882556301281247,
    -3074039370013608197,
    -637529855400303673,
    6137678347805511274,
    -7152924852417805802,
    5708223427705576541,
    -3223714144396531304,
    4358391411789012426,
    325123008708389849,
    6837621693887290924,
    4843721905315627004,
    -3212720814705499393,
    -3825019837890901156,
    4602025990114250980,
    1044646352569048800,
    9106614159853161675,
    -8394115921626182539,
    -4304087667751778808,
    2681532557646850893,
    3681559472488511871,
    -3915372517896561773,
    -2889241648411946534,
    -6564663803938238204,
    -8060058171802589521,
    581945337509520675,
    3648778920718647903,
    -4799698790548231394,
    -7602572252857820065,
    220828013409515943,
    -1072987336855386047,
    4287360518296753003,
    -4633371852008891965,
    5513660857261085186,
    -2258542936462001533,
    -8744380348503999773,
    8746140185685648781,
    228500091334420247,
    1356187007457302238,
    3019253992034194581,
    3152601605678500003,
    -8793219284148773595,
    5559581553696971176,
    4916432985369275664,
    -8559797105120221417,
    -5802598197927043732,
    2868348622579915573,
    -7224052902810357288,
    -5894682518218493085,
    2587672709781371173,
    -7706116723325376475,
    3092343956317362483,
    -5561119517847711700,
    972445599196498113,
    -1558506600978816441,
    1708913533482282562,
    -2305554874185907314,
    -6005743014309462908,
    -6653329009633068701,
    -483583197311151195,
    2488075924621352812,
    -4529369641467339140,
    -4663743555056261452,
    2997203966153298104,
    1282559373026354493,
    240113143146674385,
    8665713329246516443,
    628141331766346752,
    -4651421219668005332,
    -7750560848702540400,
    7596648026010355826,
    -3132152619100351065,
    7834161864828164065,
    7103445518877254909,
    4390861237357459201,
    -4780718172614204074,
    -319889632007444440,
    622261699494173647,
    -3186110786557562560,
    -8718967088789066690,
    -1948156510637662747,
    -8212195255998774408,
    -7028621931231314745,
    2623071828615234808,
    -4066058308780939700,
    -5484966924888173764,
    -6683604512778046238,
    -6756087640505506466,
    5256026990536851868,
    7841086888628396109,
    6640857538655893162,
    -8021284697816458310,
    -7109857044414059830,
    -1689021141511844405,
    -4298087301956291063,
    -4077748265377282003,
    -998231156719803476,
    2719520354384050532,
    9132346697815513771,
    4332154495710163773,
    -2085582442760428892,
    6994721091344268833,
    -2556143461985726874,
    -8567931991128098309,
    59934747298466858,
    -3098398008776739403,
    -265597256199410390,
    2332206071942466437,
    -7522315324568406181,
    3154897383618636503,
    -7585605855467168281,
    -6762850759087199275,
    197309393502684135,
    -8579694182469508493,
    2543179307861934850,
    4350769010207485119,
    -4468719947444108136,
    -7207776534213261296,
    -1224312577878317200,
    4287946071480840813,
    8362686366770308971,
    6486469209321732151,
    -5605644191012979782,
    -1669018511020473564,
    4450022655153542367,
    -7618176296641240059,
    -3896357471549267421,
    -4596796223304447488,
    -6531150016257070659,
    -8982326463137525940,
    -4125325062227681798,
    -1306489741394045544,
    -8338554946557245229,
    5329160409530630596,
    7790979528857726136,
    4955070238059373407,
    -4304834761432101506,
    -6215295852904371179,
    3007769226071157901,
    -6753025801236972788,
    8928702772696731736,
    7856187920214445904,
    -4748497451462800923,
    7900176660600710914,
    -7082800908938549136,
    -6797926979589575837,
    -6737316883512927978,
    4186670094382025798,
    1883939007446035042,
    -414705992779907823,
    3734134241178479257,
    4065968871360089196,
    6953124200385847784,
    -7917685222115876751,
    -7585632937840318161,
    -5567246375906782599,
    -5256612402221608788,
    3106378204088556331,
    -2894472214076325998,
    4565385105440252958,
    1979884289539493806,
    -6891578849933910383,
    3783206694208922581,
    8464961209802336085,
    2843963751609577687,
    3030678195484896323,
    -4429654462759003204,
    4459239494808162889,
    402587895800087237,
    8057891408711167515,
    4541888170938985079,
    1042662272908816815,
    -3666068979732206850,
    2647678726283249984,
    2144477441549833761,
    -3417019821499388721,
    -2105601033380872185,
    5916597177708541638,
    -8760774321402454447,
    8833658097025758785,
    5970273481425315300,
    563813119381731307,
    -6455022486202078793,
    1598828206250873866,
    -4016978389451217698,
    -2988328551145513985,
    -6071154634840136312,
    8469693267274066490,
    125672920241807416,
    -3912292412830714870,
    -2559617104544284221,
    -486523741806024092,
    -4735332261862713930,
    5923302823487327109,
    -9082480245771672572,
    -1808429243461201518,
    7990420780896957397,
    4317817392807076702,
    3625184369705367340,
    -6482649271566653105,
    -3480272027152017464,
    -3225473396345736649,
    -368878695502291645,
    -3981164001421868007,
    -8522033136963788610,
    7609280429197514109,
    3020985755112334161,
    -2572049329799262942,
    2635195723621160615,
    5144520864246028816,
    -8188285521126945980,
    1567242097116389047,
    8172389260191636581,
    -2885551685425483535,
    -7060359469858316883,
    -6480181133964513127,
    -7317004403633452381,
    6011544915663598137,
    5932255307352610768,
    2241128460406315459,
    -8327867140638080220,
    3094483003111372717,
    4583857460292963101,
    9079887171656594975,
    -384082854924064405,
    -3460631649611717935,
    4225072055348026230,
    -7385151438465742745,
    3801620336801580414,
    -399845416774701952,
    -7446754431269675473,
    7899055018877642622,
    5421679761463003041,
    5521102963086275121,
    -4975092593295409910,
    8735487530905098534,
    -7462844945281082830,
    -2080886987197029914,
    -1000715163927557685,
    -4253840471931071485,
    -5828896094657903328,
    6424174453260338141,
    359248545074932887,
    -5949720754023045210,
    -2426265837057637212,
    3030918217665093212,
    -9077771202237461772,
    -3186796180789149575,
    740416251634527158,
    -2142944401404840226,
    6951781370868335478,
    399922722363687927,
    -8928469722407522623,
    -1378421100515597285,
    -8343051178220066766,
    -3030716356046100229,
    -8811767350470065420,
    9026808440365124461,
    6440783557497587732,
    4615674634722404292,
    539897290441580544,
    2096238225866883852,
    8751955639408182687,
    -7316147128802486205,
    7381039757301768559,
    6157238513393239656,
    -1473377804940618233,
    8629571604380892756,
    5280433031239081479,
    7101611890139813254,
    2479018537985767835,
    7169176924412769570,
    -1281305539061572506,
    -7865612307799218120,
    2278447439451174845,
    3625338785743880657,
    6477479539006708521,
    8976185375579272206,
    -3712000482142939688,
    1326024180520890843,
    7537449876596048829,
    5464680203499696154,
    3189671183162196045,
    6346751753565857109,
    -8982212049534145501,
    -6127578587196093755,
    -245039190118465649,
    -6320577374581628592,
    7208698530190629697,
    7276901792339343736,
    -7490986807540332668,
    4133292154170828382,
    2918308698224194548,
    -7703910638917631350,
    -3929437324238184044,
    -4300543082831323144,
    -6344160503358350167,
    5896236396443472108,
    -758328221503023383,
    -1894351639983151068,
    -307900319840287220,
    -6278469401177312761,
    -2171292963361310674,
    8382142935188824023,
    9103922860780351547,
    4152330101494654406,
];

struct RngSource {
    tap: i32,
    feed: i32,
    vec: [u64; 607],
}

impl RngSource {
    /// `rngSource.Seed`: the 48271 Lehmer generator, seeded into the lagged
    /// Fibonacci register.
    fn new(seed: i64) -> Self {
        let mut seed = seed % INT32MAX as i64;
        if seed < 0 {
            seed += INT32MAX as i64;
        }
        if seed == 0 {
            seed = 89482311;
        }

        let mut x = seed as i32;
        let mut vec = [0u64; 607];
        let mut i = -20i32;
        while i < RNG_LEN {
            x = Self::seedrand(x);
            if i >= 0 {
                let mut u = (x as u64) << 40;
                x = Self::seedrand(x);
                u ^= (x as u64) << 20;
                x = Self::seedrand(x);
                u ^= x as u64;
                u ^= RNG_COOKED[i as usize] as u64;
                vec[i as usize] = u;
            }
            i += 1;
        }

        RngSource {
            tap: 0,
            feed: RNG_LEN - RNG_TAP,
            vec,
        }
    }

    fn seedrand(x: i32) -> i32 {
        const A: i32 = 48271;
        const Q: i32 = 44488;
        const R: i32 = 3399;
        let hi = x / Q;
        let lo = x % Q;
        let mut x = A.wrapping_mul(lo).wrapping_sub(R.wrapping_mul(hi));
        if x < 0 {
            x = x.wrapping_add(INT32MAX);
        }
        x
    }

    fn uint64(&mut self) -> u64 {
        self.tap -= 1;
        if self.tap < 0 {
            self.tap += RNG_LEN;
        }
        self.feed -= 1;
        if self.feed < 0 {
            self.feed += RNG_LEN;
        }
        let x = self.vec[self.feed as usize].wrapping_add(self.vec[self.tap as usize]);
        self.vec[self.feed as usize] = x;
        x
    }

    fn int63(&mut self) -> i64 {
        (self.uint64() & ((1u64 << 63) - 1)) as i64
    }

    fn uint32(&mut self) -> u32 {
        (self.int63() >> 31) as u32
    }

    /// Go's unexported `int31n` (Lemire reduction). Unlike `Int31n` there is no
    /// power-of-two fast path, which matters for the value stream `Shuffle`
    /// consumes.
    fn int31n(&mut self, n: i32) -> i32 {
        let mut v = self.uint32();
        let mut prod = v as u64 * n as u64;
        let mut low = prod as u32;
        if low < n as u32 {
            let thresh = (n.wrapping_neg() as u32) % (n as u32);
            while low < thresh {
                v = self.uint32();
                prod = v as u64 * n as u64;
                low = prod as u32;
            }
        }
        (prod >> 32) as i32
    }

    fn shuffle(&mut self, order: &mut [usize]) {
        let mut i = order.len();
        while i > 1 {
            i -= 1;
            let j = self.int31n((i + 1) as i32) as usize;
            order.swap(i, j);
        }
    }
}
