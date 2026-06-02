//! AES-128-CBC with PKCS#7 padding, built on `std.crypto.core.aes.Aes128`.
//!
//! Used by the Secret Service `dh-ietf1024-sha256-aes128-cbc-pkcs7`
//! transport: the per-session AES-128 key comes from
//! `dh_ietf.deriveSharedKey`, and the 16-byte IV comes from the
//! `parameters` field of each `(oayays)` secret tuple. PKCS#7 padding is
//! always added on write (including a full pad block when the plaintext is
//! already block-aligned) and is validated in constant time on read.

const std = @import("std");
const Allocator = std.mem.Allocator;
const Aes128 = std.crypto.core.aes.Aes128;

pub const block_length: usize = 16;
pub const key_length: usize = 16;

pub const Key = [key_length]u8;
pub const Iv = [block_length]u8;

pub const Error = error{
    InvalidCiphertextLength,
    InvalidPadding,
    OutOfMemory,
};

/// PKCS#7 encrypt: pad `plaintext` to the next 16-byte boundary (always at
/// least one byte of padding, even on already-aligned input) and CBC-encrypt
/// with `key` and `iv`. Caller owns the returned slice.
pub fn encrypt(
    gpa: Allocator,
    key: Key,
    iv: Iv,
    plaintext: []const u8,
) Error![]u8 {
    const pad_len: u8 = @intCast(block_length - (plaintext.len % block_length));
    const out = try gpa.alloc(u8, plaintext.len + pad_len);
    errdefer gpa.free(out);

    @memcpy(out[0..plaintext.len], plaintext);
    @memset(out[plaintext.len..], pad_len);

    encryptBlocks(key, iv, out);
    return out;
}

/// PKCS#7 decrypt: validate that `ciphertext` is non-empty and a multiple
/// of 16 bytes, CBC-decrypt with `key` and `iv`, then strip and validate
/// the PKCS#7 padding in constant time. Caller owns the returned slice.
pub fn decrypt(
    gpa: Allocator,
    key: Key,
    iv: Iv,
    ciphertext: []const u8,
) Error![]u8 {
    if (ciphertext.len == 0 or ciphertext.len % block_length != 0) {
        return Error.InvalidCiphertextLength;
    }

    const buf = try gpa.alloc(u8, ciphertext.len);
    errdefer gpa.free(buf);
    @memcpy(buf, ciphertext);

    decryptBlocks(key, iv, buf);

    const pad_len = buf[buf.len - 1];
    const valid = validatePkcs7(buf, pad_len);
    if (!valid) return Error.InvalidPadding;

    const out_len = buf.len - pad_len;
    if (gpa.resize(buf, out_len)) {
        return buf[0..out_len];
    }
    const trimmed = try gpa.alloc(u8, out_len);
    @memcpy(trimmed, buf[0..out_len]);
    gpa.free(buf);
    return trimmed;
}

/// Raw CBC encryption with no padding. `buf` must already be a multiple of
/// `block_length`; encryption is in place. Exposed for the NIST CBC-AES128
/// known-answer test below.
fn encryptBlocks(key: Key, iv: Iv, buf: []u8) void {
    std.debug.assert(buf.len % block_length == 0);
    const ctx = Aes128.initEnc(key);
    var prev: [block_length]u8 = iv;
    var i: usize = 0;
    while (i < buf.len) : (i += block_length) {
        var block: [block_length]u8 = undefined;
        for (0..block_length) |j| block[j] = buf[i + j] ^ prev[j];
        ctx.encrypt(buf[i..][0..block_length], &block);
        @memcpy(&prev, buf[i..][0..block_length]);
    }
}

/// Raw CBC decryption with no padding handling. `buf` must already be a
/// multiple of `block_length`; decryption is in place.
fn decryptBlocks(key: Key, iv: Iv, buf: []u8) void {
    std.debug.assert(buf.len % block_length == 0);
    const ctx = Aes128.initDec(key);
    var prev: [block_length]u8 = iv;
    var i: usize = 0;
    while (i < buf.len) : (i += block_length) {
        var carry: [block_length]u8 = undefined;
        @memcpy(&carry, buf[i..][0..block_length]);
        var plain: [block_length]u8 = undefined;
        ctx.decrypt(&plain, buf[i..][0..block_length]);
        for (0..block_length) |j| buf[i + j] = plain[j] ^ prev[j];
        @memcpy(&prev, &carry);
    }
}

/// Constant-time PKCS#7 padding validation. Returns true iff the tail of
/// `buf` is `pad_len` copies of `pad_len` with `pad_len` in `1..=block_length`.
fn validatePkcs7(buf: []const u8, pad_len_u8: u8) bool {
    if (pad_len_u8 == 0 or pad_len_u8 > block_length or @as(usize, pad_len_u8) > buf.len) {
        return false;
    }
    const pad_len: usize = pad_len_u8;
    var acc: u8 = 0;
    var i: usize = 0;
    while (i < block_length) : (i += 1) {
        const idx = buf.len - block_length + i;
        const should_check: u8 = @intFromBool(i + pad_len >= block_length);
        const diff: u8 = buf[idx] ^ pad_len_u8;
        acc |= diff & (@as(u8, 0) -% should_check);
    }
    return acc == 0;
}

// -- tests ------------------------------------------------------------------

const testing = std.testing;

// NIST SP 800-38A Appendix F.2.1 CBC-AES128.Encrypt example.
test "NIST SP 800-38A CBC-AES128 known-answer vector" {
    const key = [_]u8{
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
        0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
    };
    const iv = [_]u8{
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    };
    var plaintext = [_]u8{
        // block 1
        0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
        0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
        // block 2
        0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c,
        0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
        // block 3
        0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11,
        0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef,
        // block 4
        0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17,
        0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10,
    };
    const expected_ct = [_]u8{
        0x76, 0x49, 0xab, 0xac, 0x81, 0x19, 0xb2, 0x46,
        0xce, 0xe9, 0x8e, 0x9b, 0x12, 0xe9, 0x19, 0x7d,
        0x50, 0x86, 0xcb, 0x9b, 0x50, 0x72, 0x19, 0xee,
        0x95, 0xdb, 0x11, 0x3a, 0x91, 0x76, 0x78, 0xb2,
        0x73, 0xbe, 0xd6, 0xb8, 0xe3, 0xc1, 0x74, 0x3b,
        0x71, 0x16, 0xe6, 0x9e, 0x22, 0x22, 0x95, 0x16,
        0x3f, 0xf1, 0xca, 0xa1, 0x68, 0x1f, 0xac, 0x09,
        0x12, 0x0e, 0xca, 0x30, 0x75, 0x86, 0xe1, 0xa7,
    };

    encryptBlocks(key, iv, &plaintext);
    try testing.expectEqualSlices(u8, &expected_ct, &plaintext);

    // Decrypt back to the original NIST plaintext.
    decryptBlocks(key, iv, &plaintext);
    const original = [_]u8{
        0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
        0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
        0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c,
        0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
        0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11,
        0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef,
        0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17,
        0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10,
    };
    try testing.expectEqualSlices(u8, &original, &plaintext);
}

test "PKCS#7 round-trip across boundary lengths" {
    const key: Key = @splat(0x42);
    const iv: Iv = @splat(0x37);

    var rng = std.Random.DefaultPrng.init(0xDEADBEEF);
    for ([_]usize{ 0, 1, 15, 16, 17, 31, 32, 33, 1024 }) |len| {
        const pt = try testing.allocator.alloc(u8, len);
        defer testing.allocator.free(pt);
        rng.fill(pt);

        const ct = try encrypt(testing.allocator, key, iv, pt);
        defer testing.allocator.free(ct);
        // Padding adds at least one byte; block-aligned input adds a full block.
        try testing.expect(ct.len > len);
        try testing.expectEqual(@as(usize, 0), ct.len % block_length);

        const round = try decrypt(testing.allocator, key, iv, ct);
        defer testing.allocator.free(round);
        try testing.expectEqualSlices(u8, pt, round);
    }
}

test "decrypt rejects empty ciphertext" {
    const key: Key = @splat(0);
    const iv: Iv = @splat(0);
    try testing.expectError(
        Error.InvalidCiphertextLength,
        decrypt(testing.allocator, key, iv, &[_]u8{}),
    );
}

test "decrypt rejects non-block-multiple ciphertext" {
    const key: Key = @splat(0);
    const iv: Iv = @splat(0);
    const bad = [_]u8{0} ** 17;
    try testing.expectError(
        Error.InvalidCiphertextLength,
        decrypt(testing.allocator, key, iv, &bad),
    );
}

test "decrypt rejects bad PKCS#7 padding" {
    const key: Key = @splat(0xAA);
    const iv: Iv = @splat(0x55);

    // Build a ciphertext whose decrypted last byte will not be a valid pad.
    // Start from an all-zero plaintext block and corrupt the last byte of
    // the previous ciphertext block, which XORs into the last decrypted
    // byte of the final block (and therefore into the pad-length byte).
    var ct = blk: {
        const pt: [block_length]u8 = @splat(0);
        const c = try encrypt(testing.allocator, key, iv, &pt);
        break :blk c;
    };
    defer testing.allocator.free(ct);
    // The padding block is the second block (PKCS#7 appended a full block
    // of `0x10`); flip a bit in the first block's last byte so that the
    // IV-equivalent for the pad block changes.
    ct[block_length - 1] ^= 0x01;
    try testing.expectError(
        Error.InvalidPadding,
        decrypt(testing.allocator, key, iv, ct),
    );
}
