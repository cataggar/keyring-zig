//! `OpenSession` and the cached session object path.
//!
//! Only the "plain" transport is implemented: input is the algorithm name
//! `"plain"` and a variant holding an empty string; output is a variant
//! (ignored) and the new session's object path. DH-IETF transport is left
//! for a follow-up.

const std = @import("std");
const builtin = @import("builtin");
const Allocator = std.mem.Allocator;
const dbus = @import("dbus");
const wire = dbus.wire;
const message = dbus.message;
const connection = dbus.connection;

comptime {
    if (builtin.os.tag != .linux) @compileError("secret_service.session requires Linux");
}

pub const Error = connection.Error || error{OpenSessionFailed};

pub const service_destination: []const u8 = "org.freedesktop.secrets";
pub const service_path: []const u8 = "/org/freedesktop/secrets";
pub const service_interface: []const u8 = "org.freedesktop.Secret.Service";

/// Call `OpenSession("plain", <v>(""))` and return the new session path
/// duplicated into `out_gpa`. Caller frees the slice.
pub fn openPlainSession(conn: *connection.Connection, out_gpa: Allocator) Error![]u8 {
    var body: std.ArrayList(u8) = .empty;
    defer body.deinit(conn.gpa);
    var w = wire.Writer.init(conn.gpa, &body);

    try w.writeString("plain");
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
        5, 0, 0, 0, 'p', 'l', 'a', 'i', 'n', 0,
        // pad to next 1-aligned: none. signature "s": length 1 + 's' + NUL
        1, 's', 0,
        // pad to 4-aligned for the inner string length (we are at offset 13)
        0, 0, 0,
        // empty string: length 0 + NUL
        0, 0, 0, 0, 0,
    };
    try std.testing.expectEqualSlices(u8, &expected, body.items);
}
