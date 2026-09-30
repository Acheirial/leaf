//! BLAKE3 derive-key mode over a *binary* context.
//!
//! Xray derives every handshake key with `blake3.DeriveKey(k, string(ctx), key)`
//! (`Xray-core/proxy/vless/encryption/common.go:157-159`, `xor.go:13`), where
//! every context in the callers is an arbitrary byte slice: the 16 random IV
//! bytes (`client.go:111`), an encrypted header (`common.go:136`), the server's
//! pre-write random (`server.go:229`), and the 1120-byte PFS public keys. Go's
//! `string([]byte)` is a byte-for-byte conversion, so the context is binary.
//!
//! The `blake3` crate exposes derive-key only over a UTF-8 `&str`
//! (`derive_key`, `Hasher::new_derive_key`, `hazmat::hash_derive_key_context`),
//! and its `hazmat` primitives that *do* take bytes are not wired for the
//! `DERIVE_KEY_CONTEXT` flag. Building a `&str` from non-UTF-8 bytes would be
//! undefined behaviour, so the primitive is implemented here instead.
//!
//! The algorithm is the BLAKE3 specification (section 2.6 of the paper):
//!
//! 1. `context_key = BLAKE3(context, key = IV, flags = DERIVE_KEY_CONTEXT)`,
//!    taking the first 32 bytes of the root output;
//! 2. `output = BLAKE3(material, key = context_key, flags = DERIVE_KEY_MATERIAL)`,
//!    taking the first 32 bytes of the root output.
//!
//! This mirrors exactly `blake3::derive_key` / `hazmat::hash_derive_key_context`
//! (`blake3-1.8.7/src/lib.rs:1003-1008`, `src/hazmat.rs:560-565`): the context
//! hash uses the *standard* IV plus the `DERIVE_KEY_CONTEXT` flag, and the
//! material hash replaces the initial chaining value with the context key and
//! sets `DERIVE_KEY_MATERIAL`. The unit tests below pin the implementation to
//! the crate's own output for ASCII contexts, which is what makes the binary
//! path trustworthy.
//!
//! Only the serial (no SIMD, single-threaded) hasher is implemented; the tree
//! structure, chunk counters and flags follow the specification so that inputs
//! longer than one 1024-byte chunk are hashed correctly.

const IV: [u32; 8] = [
    0x6A09_E667,
    0xBB67_AE85,
    0x3C6E_F372,
    0xA54F_F53A,
    0x510E_527F,
    0x9B05_688C,
    0x1F83_D9AB,
    0x5BE0_CD19,
];

const BLOCK_LEN: usize = 64;
const CHUNK_LEN: usize = 1024;

const CHUNK_START: u32 = 1 << 0;
const CHUNK_END: u32 = 1 << 1;
const PARENT: u32 = 1 << 2;
const ROOT: u32 = 1 << 3;
const DERIVE_KEY_CONTEXT: u32 = 1 << 5;
const DERIVE_KEY_MATERIAL: u32 = 1 << 6;

const MSG_SCHEDULE: [[usize; 16]; 7] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8],
    [3, 4, 10, 12, 13, 2, 7, 14, 6, 5, 9, 0, 11, 15, 8, 1],
    [10, 7, 12, 9, 14, 3, 13, 15, 4, 0, 11, 2, 5, 8, 1, 6],
    [12, 13, 9, 11, 15, 10, 14, 8, 7, 2, 5, 3, 0, 1, 6, 4],
    [9, 14, 11, 5, 8, 12, 15, 1, 13, 3, 0, 10, 2, 6, 4, 7],
    [11, 15, 5, 0, 1, 9, 8, 6, 14, 10, 2, 12, 3, 4, 7, 13],
];

#[inline(always)]
fn g(state: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize, x: u32, y: u32) {
    state[a] = state[a].wrapping_add(state[b]).wrapping_add(x);
    state[d] = (state[d] ^ state[a]).rotate_right(16);
    state[c] = state[c].wrapping_add(state[d]);
    state[b] = (state[b] ^ state[c]).rotate_right(12);
    state[a] = state[a].wrapping_add(state[b]).wrapping_add(y);
    state[d] = (state[d] ^ state[a]).rotate_right(8);
    state[c] = state[c].wrapping_add(state[d]);
    state[b] = (state[b] ^ state[c]).rotate_right(7);
}

#[inline(always)]
fn round(state: &mut [u32; 16], msg: &[u32; 16], r: usize) {
    let s = MSG_SCHEDULE[r];
    g(state, 0, 4, 8, 12, msg[s[0]], msg[s[1]]);
    g(state, 1, 5, 9, 13, msg[s[2]], msg[s[3]]);
    g(state, 2, 6, 10, 14, msg[s[4]], msg[s[5]]);
    g(state, 3, 7, 11, 15, msg[s[6]], msg[s[7]]);
    g(state, 0, 5, 10, 15, msg[s[8]], msg[s[9]]);
    g(state, 1, 6, 11, 12, msg[s[10]], msg[s[11]]);
    g(state, 2, 7, 8, 13, msg[s[12]], msg[s[13]]);
    g(state, 3, 4, 9, 14, msg[s[14]], msg[s[15]]);
}

/// The BLAKE3 compression function, returning the full 16-word extended output.
fn compress(
    cv: &[u32; 8],
    block: &[u32; 16],
    counter: u64,
    block_len: u32,
    flags: u32,
) -> [u32; 16] {
    let mut state = [
        cv[0],
        cv[1],
        cv[2],
        cv[3],
        cv[4],
        cv[5],
        cv[6],
        cv[7],
        IV[0],
        IV[1],
        IV[2],
        IV[3],
        counter as u32,
        (counter >> 32) as u32,
        block_len,
        flags,
    ];
    for r in 0..7 {
        round(&mut state, block, r);
    }
    for i in 0..8 {
        state[i] ^= state[i + 8];
        state[i + 8] ^= cv[i];
    }
    state
}

fn words_from_block(block: &[u8; BLOCK_LEN]) -> [u32; 16] {
    let mut words = [0u32; 16];
    for (i, w) in words.iter_mut().enumerate() {
        let b = &block[i * 4..i * 4 + 4];
        *w = u32::from_le_bytes([b[0], b[1], b[2], b[3]]);
    }
    words
}

fn words_from_32(bytes: &[u8; 32]) -> [u32; 8] {
    let mut words = [0u32; 8];
    for (i, w) in words.iter_mut().enumerate() {
        let b = &bytes[i * 4..i * 4 + 4];
        *w = u32::from_le_bytes([b[0], b[1], b[2], b[3]]);
    }
    words
}

/// The first 32 bytes of a compression output: the chaining value.
fn cv_bytes(out: &[u32; 16]) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    for i in 0..8 {
        bytes[i * 4..i * 4 + 4].copy_from_slice(&out[i].to_le_bytes());
    }
    bytes
}

/// Reduce one chunk to its final block plus the state needed to compress it.
///
/// Returns `(chaining_value_before_the_last_block, last_block, last_block_len,
/// last_block_flags)`. `last_block_flags` already carries `CHUNK_START` when the
/// chunk is a single block (including the empty chunk) and always `CHUNK_END`.
fn chunk_output(
    chunk: &[u8],
    key: &[u32; 8],
    counter: u64,
    flags: u32,
) -> ([u32; 8], [u8; BLOCK_LEN], u32, u32) {
    let mut cv = *key;
    let mut offset = 0usize;
    let mut first = true;
    loop {
        let take = (chunk.len() - offset).min(BLOCK_LEN);
        let mut block = [0u8; BLOCK_LEN];
        block[..take].copy_from_slice(&chunk[offset..offset + take]);
        let last = offset + take >= chunk.len();
        let mut block_flags = flags;
        if first {
            block_flags |= CHUNK_START;
        }
        if last {
            block_flags |= CHUNK_END;
            return (cv, block, take as u32, block_flags);
        }
        cv = first_cv(&compress(
            &cv,
            &words_from_block(&block),
            counter,
            take as u32,
            block_flags,
        ));
        first = false;
        offset += take;
    }
}

/// The 8-word chaining value (first 32 bytes) of a compression output.
fn first_cv(out: &[u32; 16]) -> [u32; 8] {
    let mut cv = [0u32; 8];
    cv.copy_from_slice(&out[..8]);
    cv
}

fn chunk_cv(chunk: &[u8], key: &[u32; 8], counter: u64, flags: u32) -> [u8; 32] {
    let (cv, block, block_len, block_flags) = chunk_output(chunk, key, counter, flags);
    cv_bytes(&compress(
        &cv,
        &words_from_block(&block),
        counter,
        block_len,
        block_flags,
    ))
}

fn chunk_root(chunk: &[u8], key: &[u32; 8], counter: u64, flags: u32) -> [u8; 32] {
    let (cv, block, block_len, block_flags) = chunk_output(chunk, key, counter, flags);
    cv_bytes(&compress(
        &cv,
        &words_from_block(&block),
        counter,
        block_len,
        block_flags | ROOT,
    ))
}

fn parent(key: &[u32; 8], left: &[u8; 32], right: &[u8; 32], flags: u32) -> [u8; 32] {
    let mut block = [0u8; BLOCK_LEN];
    block[..32].copy_from_slice(left);
    block[32..].copy_from_slice(right);
    cv_bytes(&compress(
        key,
        &words_from_block(&block),
        0,
        BLOCK_LEN as u32,
        flags | PARENT,
    ))
}

fn parent_root(key: &[u32; 8], left: &[u8; 32], right: &[u8; 32], flags: u32) -> [u8; 32] {
    let mut block = [0u8; BLOCK_LEN];
    block[..32].copy_from_slice(left);
    block[32..].copy_from_slice(right);
    cv_bytes(&compress(
        key,
        &words_from_block(&block),
        0,
        BLOCK_LEN as u32,
        flags | PARENT | ROOT,
    ))
}

/// The largest power of two less than or equal to `n`.
fn largest_power_of_two_leq(n: usize) -> usize {
    ((n / 2) + 1).next_power_of_two()
}

/// The number of bytes in the left subtree for a multi-chunk input.
///
/// This is the canonical split from the BLAKE3 paper, matching the crate's
/// `left_subtree_len` usage (`blake3-1.8.7/src/lib.rs`).
fn left_len(content_len: usize) -> usize {
    debug_assert!(content_len > CHUNK_LEN);
    let full_chunks = (content_len - 1) / CHUNK_LEN;
    largest_power_of_two_leq(full_chunks) * CHUNK_LEN
}

fn subtree_or_chunk(input: &[u8], key: &[u32; 8], counter: u64, flags: u32) -> [u8; 32] {
    if input.len() <= CHUNK_LEN {
        chunk_cv(input, key, counter, flags)
    } else {
        subtree_cv(input, key, counter, flags)
    }
}

fn subtree_cv(input: &[u8], key: &[u32; 8], counter: u64, flags: u32) -> [u8; 32] {
    let left = left_len(input.len());
    let left_cv = subtree_or_chunk(&input[..left], key, counter, flags);
    let right_counter = counter + (left / CHUNK_LEN) as u64;
    let right_cv = subtree_or_chunk(&input[left..], key, right_counter, flags);
    parent(key, &left_cv, &right_cv, flags)
}

/// Hash `input` with the given initial chaining value and mode flag, returning
/// the first 32 bytes of the root output.
fn hash_root(input: &[u8], key: &[u32; 8], flags: u32) -> [u8; 32] {
    if input.len() <= CHUNK_LEN {
        chunk_root(input, key, 0, flags)
    } else {
        let left = left_len(input.len());
        let left_cv = subtree_or_chunk(&input[..left], key, 0, flags);
        let right_cv = subtree_or_chunk(&input[left..], key, (left / CHUNK_LEN) as u64, flags);
        parent_root(key, &left_cv, &right_cv, flags)
    }
}

/// BLAKE3 derive-key over an arbitrary (possibly non-UTF-8) context.
///
/// Byte-for-byte identical to `blake3::derive_key(context, material)` whenever
/// `context` is valid UTF-8; see the tests below.
pub fn derive_key(context: &[u8], material: &[u8]) -> [u8; 32] {
    let context_key = hash_root(context, &IV, DERIVE_KEY_CONTEXT);
    let key_words = words_from_32(&context_key);
    hash_root(material, &key_words, DERIVE_KEY_MATERIAL)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The whole point of this module: for every ASCII context the output must
    /// be byte-identical to the `blake3` crate's derive-key implementation.
    /// Sizes are chosen to cross the 64-byte block and 1024-byte chunk
    /// boundaries so the tree/framing rules are exercised, not just the
    /// single-block fast path.
    #[test]
    fn matches_blake3_crate_for_ascii_contexts_and_materials() {
        let contexts: &[&str] = &[
            "",
            "VLESS",
            "a",
            "0123456789abcdef",
            &"c".repeat(63),
            &"d".repeat(64),
            &"e".repeat(65),
            &"f".repeat(1000),
            &"g".repeat(1023),
            &"h".repeat(1024),
            &"i".repeat(1025),
            &"j".repeat(2048),
            &"k".repeat(3000),
            &"l".repeat(4096),
            &"m".repeat(5000),
        ];
        for context in contexts {
            for material_len in [0usize, 1, 31, 32, 64, 65, 96, 1024, 1025, 2000] {
                let material: Vec<u8> = (0..material_len).map(|i| (i % 251) as u8).collect();
                let ours = derive_key(context.as_bytes(), &material);
                let theirs = blake3::derive_key(context, &material);
                assert_eq!(
                    ours,
                    theirs,
                    "context len {} material len {}",
                    context.len(),
                    material_len
                );
            }
        }
    }

    /// The crate's `Hasher::new_derive_key` path must agree with ours too, so
    /// the equivalence is not an artifact of `derive_key` alone.
    #[test]
    fn matches_hasher_new_derive_key() {
        for (context, material) in [
            ("VLESS", &b"hello world"[..]),
            (
                "some longer ascii context that is definitely over one block long ............",
                &b""[..],
            ),
        ] {
            let mut hasher = blake3::Hasher::new_derive_key(context);
            hasher.update(material);
            let theirs: [u8; 32] = hasher.finalize().into();
            assert_eq!(derive_key(context.as_bytes(), material), theirs);
        }
    }

    /// A binary context is the actual requirement; assert it is deterministic
    /// and context-sensitive (the exact value is pinned against the
    /// ASCII-equality above, which covers the same code path).
    #[test]
    fn binary_context_is_deterministic_and_distinct() {
        let material = b"key material";
        let a = derive_key(&[0u8, 1, 2, 3], material);
        let b = derive_key(&[0u8, 1, 2, 3], material);
        let c = derive_key(&[4u8, 5, 6, 7], material);
        assert_eq!(a, b);
        assert_ne!(a, c);

        // A non-UTF-8 context (0xFF is invalid UTF-8) must hash without panic;
        // this is exactly what the crate cannot express.
        let ctx: Vec<u8> = vec![0xFF, 0xFE, 0x80, 0x00, 0xC0, 0x80];
        let _ = derive_key(&ctx, material);
    }
}
