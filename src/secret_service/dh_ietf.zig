//! Diffie-Hellman key agreement for the
//! `dh-ietf1024-sha256-aes128-cbc-pkcs7` Secret Service transport.
//!
//! The math is RFC 2409 §6.2 (Oakley Group 2 / "MODP-1024"): a 1024-bit
//! safe prime with generator `2`. After the public-key exchange the shared
//! secret `Z = peer^x mod p` is serialized to a left-padded 128-byte
//! big-endian buffer and fed into HKDF-SHA256 with an empty salt and empty
//! info to derive a 16-byte AES-128 key, matching what `libsecret` does.
//!
//! The constant-time modular exponentiation comes from `std.crypto.ff`, so
//! no third-party big-int dependency is needed.

const std = @import("std");
const Allocator = std.mem.Allocator;
const HkdfSha256 = std.crypto.kdf.hkdf.HkdfSha256;

pub const prime_bytes: usize = 128;
pub const private_bytes: usize = 128;
pub const public_bytes: usize = 128;
pub const aes_key_bytes: usize = 16;

/// RFC 2409 §6.2 prime, big-endian (1024 bits, 128 bytes).
pub const prime_be: [prime_bytes]u8 = .{
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xC9, 0x0F, 0xDA, 0xA2, 0x21, 0x68, 0xC2, 0x34,
    0xC4, 0xC6, 0x62, 0x8B, 0x80, 0xDC, 0x1C, 0xD1, 0x29, 0x02, 0x4E, 0x08, 0x8A, 0x67, 0xCC, 0x74,
    0x02, 0x0B, 0xBE, 0xA6, 0x3B, 0x13, 0x9B, 0x22, 0x51, 0x4A, 0x08, 0x79, 0x8E, 0x34, 0x04, 0xDD,
    0xEF, 0x95, 0x19, 0xB3, 0xCD, 0x3A, 0x43, 0x1B, 0x30, 0x2B, 0x0A, 0x6D, 0xF2, 0x5F, 0x14, 0x37,
    0x4F, 0xE1, 0x35, 0x6D, 0x6D, 0x51, 0xC2, 0x45, 0xE4, 0x85, 0xB5, 0x76, 0x62, 0x5E, 0x7E, 0xC6,
    0xF4, 0x4C, 0x42, 0xE9, 0xA6, 0x37, 0xED, 0x6B, 0x0B, 0xFF, 0x5C, 0xB6, 0xF4, 0x06, 0xB7, 0xED,
    0xEE, 0x38, 0x6B, 0xFB, 0x5A, 0x89, 0x9F, 0xA5, 0xAE, 0x9F, 0x24, 0x11, 0x7C, 0x4B, 0x1F, 0xE6,
    0x49, 0x28, 0x66, 0x51, 0xEC, 0xE6, 0x53, 0x81, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
};

/// Generator `g = 2`, encoded as a 128-byte big-endian buffer so it can be
/// used directly as a field element with the same length as the modulus.
pub const generator_be: [prime_bytes]u8 = blk: {
    var g: [prime_bytes]u8 = @splat(0);
    g[prime_bytes - 1] = 2;
    break :blk g;
};

pub const KeyPair = struct {
    private: [private_bytes]u8,
    public: [public_bytes]u8,
};

pub const SharedKey = [aes_key_bytes]u8;

pub const Error = error{
    InvalidPeerKey,
    DerivationFailed,
};

const Modulus = std.crypto.ff.Modulus(1024);
const Fe = Modulus.Fe;

/// Generate a fresh 1024-bit DH key pair. The private exponent is drawn as
/// 128 random bytes with the high bit cleared, guaranteeing
/// `1 <= x < 2^1023 < p - 1` so that `Fe.pow` never sees a zero exponent
/// and the result is well-defined.
pub fn generateKeyPair(random: std.Random) Error!KeyPair {
    var kp: KeyPair = undefined;

    var tries: usize = 0;
    while (true) : (tries += 1) {
        random.bytes(&kp.private);
        // Clear the top bit so x < 2^1023 < p, leaving plenty of headroom
        // below `p - 1` and avoiding any rejection sampling against `p`.
        kp.private[0] &= 0x7F;
        if (!isAllZero(&kp.private)) break;
        if (tries > 4) return Error.DerivationFailed; // pathological RNG
    }

    const m = Modulus.fromBytes(&prime_be, .big) catch return Error.DerivationFailed;
    const g = Fe.fromBytes(m, &generator_be, .big) catch return Error.DerivationFailed;
    const pub_fe = m.powWithEncodedExponent(g, &kp.private, .big) catch return Error.DerivationFailed;
    pub_fe.toBytes(&kp.public, .big) catch return Error.DerivationFailed;
    return kp;
}

/// Compute `Z = peer^private mod p`, left-pad to 128 bytes, and run it
/// through HKDF-SHA256 with empty salt and empty info to derive a 16-byte
/// AES-128 session key.
pub fn deriveSharedKey(
    private: [private_bytes]u8,
    peer_public_be: []const u8,
) Error!SharedKey {
    if (peer_public_be.len == 0 or peer_public_be.len > public_bytes) {
        return Error.InvalidPeerKey;
    }

    var peer_padded: [public_bytes]u8 = @splat(0);
    @memcpy(peer_padded[public_bytes - peer_public_be.len ..], peer_public_be);

    if (isAllZero(&peer_padded)) return Error.InvalidPeerKey;

    const m = Modulus.fromBytes(&prime_be, .big) catch return Error.DerivationFailed;
    const peer_fe = Fe.fromBytes(m, &peer_padded, .big) catch return Error.InvalidPeerKey;
    const z_fe = m.powWithEncodedExponent(peer_fe, &private, .big) catch return Error.DerivationFailed;

    var z_bytes: [prime_bytes]u8 = undefined;
    z_fe.toBytes(&z_bytes, .big) catch return Error.DerivationFailed;

    // HKDF-SHA256 with NULL salt (RFC 5869: treated as HashLen zeroes;
    // HMAC zero-pads either way) and empty info, output length 16.
    const prk = HkdfSha256.extract(&[_]u8{}, &z_bytes);
    var key: SharedKey = undefined;
    HkdfSha256.expand(&key, &[_]u8{}, prk);
    return key;
}

fn isAllZero(bytes: []const u8) bool {
    var acc: u8 = 0;
    for (bytes) |b| acc |= b;
    return acc == 0;
}

// -- tests ------------------------------------------------------------------

const testing = std.testing;

test "generator constant is g = 2 left-padded" {
    try testing.expectEqual(@as(u8, 2), generator_be[prime_bytes - 1]);
    for (generator_be[0 .. prime_bytes - 1]) |b| try testing.expectEqual(@as(u8, 0), b);
}

test "generateKeyPair produces a non-zero public key" {
    var prng = std.Random.DefaultPrng.init(0xC0FFEE);
    const kp = try generateKeyPair(prng.random());
    try testing.expect(!isAllZero(&kp.public));
    try testing.expectEqual(@as(u8, 0), kp.private[0] & 0x80);
}

test "deriveSharedKey rejects empty peer key" {
    try testing.expectError(Error.InvalidPeerKey, deriveSharedKey(@splat(1), &[_]u8{}));
}

test "deriveSharedKey rejects zero peer key" {
    const zeros: [public_bytes]u8 = @splat(0);
    try testing.expectError(Error.InvalidPeerKey, deriveSharedKey(@splat(1), &zeros));
}

test "deriveSharedKey is symmetric: alice and bob agree" {
    var prng = std.Random.DefaultPrng.init(0xA11CE);
    const a = try generateKeyPair(prng.random());
    const b = try generateKeyPair(prng.random());

    const k_a = try deriveSharedKey(a.private, &b.public);
    const k_b = try deriveSharedKey(b.private, &a.public);

    try testing.expectEqualSlices(u8, &k_a, &k_b);
}

test "deriveSharedKey handles peer key shorter than the prime" {
    // Build a synthetic short peer key by stripping leading zeros after
    // computing a normal exchange. The padded and the raw forms must
    // produce the same shared key.
    var prng = std.Random.DefaultPrng.init(0xB0B);
    const a = try generateKeyPair(prng.random());
    const b = try generateKeyPair(prng.random());

    var trimmed: []const u8 = &b.public;
    while (trimmed.len > 1 and trimmed[0] == 0) trimmed = trimmed[1..];

    const k_full = try deriveSharedKey(a.private, &b.public);
    const k_trim = try deriveSharedKey(a.private, trimmed);

    try testing.expectEqualSlices(u8, &k_full, &k_trim);
}

// Known-answer vector: `private = 2`, peer public = `g = 2`, so
// `Z = 2^2 mod p = 4`. After HKDF-SHA256(salt=empty, ikm=Z_padded_to_128,
// info=empty, L=16) the derived key is fully determined. The expected key
// below was computed offline with Python's `cryptography` package:
//
//   from cryptography.hazmat.primitives.kdf.hkdf import HKDF
//   from cryptography.hazmat.primitives import hashes
//   ikm = b"\x00"*126 + b"\x00\x04"
//   HKDF(hashes.SHA256(), 16, None, None).derive(ikm).hex()
test "deriveSharedKey known-answer vector (Z = 4)" {
    var priv: [private_bytes]u8 = @splat(0);
    priv[private_bytes - 1] = 2;
    const key = try deriveSharedKey(priv, &generator_be);

    const expected_hex = "3677030fa931afadb2e6510f35e79879";
    var expected: [aes_key_bytes]u8 = undefined;
    _ = try std.fmt.hexToBytes(&expected, expected_hex);
    try testing.expectEqualSlices(u8, &expected, &key);
}

// Second known-answer vector with small exponents on both sides. With
// `x = 5`, `y = 7`, `g = 2`, `A = g^x mod p = 32`, `B = g^y mod p = 128`,
// `Z = B^x mod p = A^y mod p = 2^35`. The padded `Z` is hashed through
// HKDF-SHA256(salt=empty, info=empty, L=16). Reference values computed
// offline with Python:
//
//   p   = int("FFFFFFFF...FFFFFFFF", 16)   # RFC 2409 §6.2
//   Z   = pow(2, 5*7, p).to_bytes(128, "big")
//   prk = hmac.new(b"\x00"*32, Z, hashlib.sha256).digest()
//   key = hmac.new(prk, b"\x01", hashlib.sha256).digest()[:16]
test "deriveSharedKey known-answer vector (x=5, y=7)" {
    var x: [private_bytes]u8 = @splat(0);
    x[private_bytes - 1] = 5;
    var y: [private_bytes]u8 = @splat(0);
    y[private_bytes - 1] = 7;

    // Compute A = g^x and B = g^y via our own generator path, then verify
    // the well-known small public-key values.
    const m = try Modulus.fromBytes(&prime_be, .big);
    const g_fe = try Fe.fromBytes(m, &generator_be, .big);
    const a_fe = try m.powWithEncodedExponent(g_fe, &x, .big);
    const b_fe = try m.powWithEncodedExponent(g_fe, &y, .big);

    var a_bytes: [public_bytes]u8 = undefined;
    var b_bytes: [public_bytes]u8 = undefined;
    try a_fe.toBytes(&a_bytes, .big);
    try b_fe.toBytes(&b_bytes, .big);
    try testing.expectEqual(@as(u8, 0x20), a_bytes[public_bytes - 1]); // 2^5 = 32
    try testing.expectEqual(@as(u8, 0x80), b_bytes[public_bytes - 1]); // 2^7 = 128

    const k_a = try deriveSharedKey(x, &b_bytes);
    const k_b = try deriveSharedKey(y, &a_bytes);
    try testing.expectEqualSlices(u8, &k_a, &k_b);

    const expected_hex = "aff01ea9e17aee57325765b5e9f3c619";
    var expected: [aes_key_bytes]u8 = undefined;
    _ = try std.fmt.hexToBytes(&expected, expected_hex);
    try testing.expectEqualSlices(u8, &expected, &k_a);
}
