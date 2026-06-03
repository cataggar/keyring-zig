//! `OpenSession` and the cached session object path.
//!
//! Two transports are supported. `.plain` is the default and matches the
//! original behavior: input is the algorithm name `"plain"` and a variant
//! holding an empty string. `.dh_ietf` negotiates
//! `dh-ietf1024-sha256-aes128-cbc-pkcs7`, exchanging 1024-bit MODP DH
//! public keys (RFC 2409 §6.2) and deriving a 16-byte AES-128 key via
//! HKDF-SHA256. The derived key is returned alongside the session object
//! path so the caller can use it to (de)encrypt secret values per
//! `org.freedesktop.Secret.Service`.

const std = @import("std");
const builtin = @import("builtin");
const Allocator = std.mem.Allocator;
const dbus = @import("dbus");
const wire = dbus.wire;
const message = dbus.message;
const connection = dbus.connection;

const dh_ietf = @import("dh_ietf.zig");

comptime {
    if (builtin.os.tag != .linux) @compileError("secret_service.session requires Linux");
}

pub const Error = connection.Error || error{
    OpenSessionFailed,
    TransportNotSupported,
};

pub const service_destination: []const u8 = "org.freedesktop.secrets";
pub const service_path: []const u8 = "/org/freedesktop/secrets";
pub const service_interface: []const u8 = "org.freedesktop.Secret.Service";

pub const dh_algorithm: []const u8 = "dh-ietf1024-sha256-aes128-cbc-pkcs7";
pub const plain_algorithm: []const u8 = "plain";

pub const Transport = enum { plain, dh_ietf };

pub const OpenResult = struct {
    /// Allocated with `out_gpa`. Caller owns and frees.
    path: []u8,
    /// Set only when `transport == .dh_ietf`.
    key: ?[dh_ietf.aes_key_bytes]u8,
};

/// Call `OpenSession(algorithm, <v>(...))` for the requested transport and
/// return the new session path and (for `.dh_ietf`) the derived AES-128
/// session key.
pub fn openSession(
    conn: *connection.Connection,
    transport: Transport,
    out_gpa: Allocator,
) Error!OpenResult {
    switch (transport) {
        .plain => {
            const path = try openPlainSession(conn, out_gpa);
            return .{ .path = path, .key = null };
        },
        .dh_ietf => return openDhSession(conn, out_gpa),
    }
}

/// Convenience wrapper used by callers that only ever want the plain
/// transport. Kept for backwards compatibility with the original API; new
/// code should prefer `openSession`.
pub fn openPlainSession(conn: *connection.Connection, out_gpa: Allocator) Error![]u8 {
    var body: std.ArrayList(u8) = .empty;
    defer body.deinit(conn.gpa);
    var w = wire.Writer.init(conn.gpa, &body);

    try w.writeString(plain_algorithm);
    // Variant containing an empty string.
    try w.writeSignatureValue("s");
    try w.writeString("");

    var reply = try connection.call(conn, .{
        .destination = service_destination,
        .path = service_path,
        .interface = service_interface,
        .member = "OpenSession",
        .signature = "sv",
        .body = body.items,
    });
    defer reply.deinit();
    if (reply.err) |_| return Error.OpenSessionFailed;

    var r = wire.Reader.init(reply.body);
    // Skip the output variant.
    const out_sig = try r.readSignatureValue();
    try skipVariantValue(&r, out_sig);
    const path = try r.readObjectPath();
    return try out_gpa.dupe(u8, path);
}

fn openDhSession(conn: *connection.Connection, out_gpa: Allocator) Error!OpenResult {
    var seed: [std.Random.DefaultCsprng.secret_seed_length]u8 = undefined;
    secureRandom(&seed);
    var rng = std.Random.DefaultCsprng.init(seed);
    const kp = dh_ietf.generateKeyPair(rng.random()) catch return Error.OpenSessionFailed;

    var body: std.ArrayList(u8) = .empty;
    defer body.deinit(conn.gpa);
    var w = wire.Writer.init(conn.gpa, &body);

    try w.writeString(dh_algorithm);
    // Variant containing `ay` with our 128-byte DH public key.
    try w.writeSignatureValue("ay");
    {
        const arr = try w.beginArray(1);
        try w.writeBytes(&kp.public);
        w.endArray(arr);
    }

    var reply = try connection.call(conn, .{
        .destination = service_destination,
        .path = service_path,
        .interface = service_interface,
        .member = "OpenSession",
        .signature = "sv",
        .body = body.items,
    });
    defer reply.deinit();
    if (reply.err) |e| {
        if (std.mem.endsWith(u8, e.name, ".NotSupported")) return Error.TransportNotSupported;
        return Error.OpenSessionFailed;
    }

    var r = wire.Reader.init(reply.body);
    const out_sig = try r.readSignatureValue();
    if (!std.mem.eql(u8, out_sig, "ay")) return Error.OpenSessionFailed;
    const peer_pub = try readAyValue(&r);
    const path = try r.readObjectPath();

    const key = dh_ietf.deriveSharedKey(kp.private, peer_pub) catch
        return Error.OpenSessionFailed;
    const path_owned = try out_gpa.dupe(u8, path);
    return .{ .path = path_owned, .key = key };
}

fn readAyValue(r: *wire.Reader) Error![]const u8 {
    const arr = try r.beginArray(1);
    const bytes = try r.readBytes(arr.end - r.pos);
    return bytes;
}

fn skipVariantValue(r: *wire.Reader, sig: []const u8) wire.ReadError!void {
    if (sig.len == 0) return;
    switch (sig[0]) {
        'y' => _ = try r.readByte(),
        'b', 'u', 'i' => _ = try r.readU32(),
        'n', 'q' => _ = try r.readU16(),
        'x', 't', 'd' => _ = try r.readU64(),
        's', 'o' => _ = try r.readString(),
        'g' => _ = try r.readSignatureValue(),
        'a' => {
            // Only `ay` is expected from OpenSession output; skip its bytes.
            if (sig.len >= 2 and sig[1] == 'y') {
                const arr = try r.beginArray(1);
                _ = try r.readBytes(arr.end - r.pos);
            } else return wire.ReadError.InvalidSignature;
        },
        else => return wire.ReadError.InvalidSignature,
    }
}

fn seedFromOs() u64 {
    var seed: u64 = undefined;
    secureRandom(std.mem.asBytes(&seed));
    return seed;
}

/// Fill `buf` with bytes from the kernel CSPRNG via the `getrandom`
/// syscall. On the extremely rare event that the syscall fails (no
/// `/dev/urandom`, sandboxed without entropy), we abort: a non-random
/// IV or DH private key would silently weaken the transport.
pub fn secureRandom(buf: []u8) void {
    var remaining = buf;
    while (remaining.len > 0) {
        const rc = std.os.linux.getrandom(remaining.ptr, remaining.len, 0);
        const err = std.os.linux.errno(rc);
        switch (err) {
            .SUCCESS => {
                const n: usize = @intCast(rc);
                if (n == 0) std.debug.panic("getrandom returned 0", .{});
                remaining = remaining[n..];
            },
            .INTR => continue,
            else => std.debug.panic("getrandom syscall failed: {t}", .{err}),
        }
    }
}

test "openPlainSession marshalling is correct" {
    // Verify by hand: marshal "plain" + v("") and check the byte sequence.
    var body: std.ArrayList(u8) = .empty;
    defer body.deinit(std.testing.allocator);
    var w = wire.Writer.init(std.testing.allocator, &body);
    try w.writeString("plain");
    try w.writeSignatureValue("s");
    try w.writeString("");

    const expected = [_]u8{
        // string "plain" (length 5 + 5 bytes + NUL)
        5, 0,   0, 0, 'p', 'l', 'a', 'i', 'n', 0,
        // pad to next 1-aligned: none. signature "s": length 1 + 's' + NUL
        1, 's', 0,
        // pad to 4-aligned for the inner string length (we are at offset 13)
        0, 0,   0,
        // empty string: length 0 + NUL
          0,   0,   0,   0,
        0,
    };
    try std.testing.expectEqualSlices(u8, &expected, body.items);
}

test "DH OpenSession body marshals as `s + v(ay)`" {
    // Round-trip the body the openDhSession path constructs so future
    // refactors do not silently break the wire format. We use a fixed
    // 4-byte public key for compactness; the production code always
    // emits 128 bytes.
    var body: std.ArrayList(u8) = .empty;
    defer body.deinit(std.testing.allocator);
    var w = wire.Writer.init(std.testing.allocator, &body);

    try w.writeString(dh_algorithm);
    try w.writeSignatureValue("ay");
    const pub_bytes = [_]u8{ 0xDE, 0xAD, 0xBE, 0xEF };
    {
        const arr = try w.beginArray(1);
        try w.writeBytes(&pub_bytes);
        w.endArray(arr);
    }

    var r = wire.Reader.init(body.items);
    const algo = try r.readString();
    try std.testing.expectEqualStrings(dh_algorithm, algo);
    const out_sig = try r.readSignatureValue();
    try std.testing.expectEqualStrings("ay", out_sig);
    const arr = try r.beginArray(1);
    const bytes = try r.readBytes(arr.end - r.pos);
    try std.testing.expectEqualSlices(u8, &pub_bytes, bytes);
}
