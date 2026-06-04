//! Marshalling helpers specific to `org.freedesktop.Secret.Service`.
//!
//! The Secret Service stores keys as items inside collections. Items are
//! tagged with a free-form attribute dict (`a{ss}`); a "schema" name is
//! conventionally written into the `xdg:schema` attribute. To stay
//! compatible with libsecret and Python `keyring`, we use the same schema
//! name and attribute keys (`service`, `username`).

const std = @import("std");
const Allocator = std.mem.Allocator;
const wire = @import("dbus").wire;

const aes_cbc = @import("aes_cbc.zig");

/// Schema name written into the `xdg:schema` attribute. Matches libsecret's
/// `SECRET_SCHEMA_TYPE_NOTE`-equivalent name used by the existing
/// `keyring-linux.zig` backend so items written by either implementation are
/// readable by the other.
pub const schema_name: []const u8 = "org.freedesktop.Secret.Generic";

pub const Attributes = struct {
    service: []const u8,
    username: []const u8,
};

/// Per-write cipher used for `(oayays)` secret tuples. `.plain` keeps the
/// historical behavior (empty `parameters`, raw value). `.dh_ietf` carries
/// a 16-byte AES-128 key plus a 16-byte IV that gets serialized into the
/// `parameters` field; the value is the CBC-PKCS#7 ciphertext.
pub const SessionCipher = union(enum) {
    plain,
    dh_ietf: struct {
        key: [aes_cbc.key_length]u8,
        iv: [aes_cbc.block_length]u8,
    },
};

pub const WriteCreateItemError = wire.WriteError || aes_cbc.Error;
pub const DecryptSecretError = aes_cbc.Error || error{InvalidParameters};

/// Marshal an `a{ss}` attributes dict with `service`, `username`, and
/// `xdg:schema` entries. Entries are sorted by key to keep the bytes
/// deterministic for testing.
pub fn writeAttributes(gpa: Allocator, buf: *std.ArrayList(u8), attrs: Attributes) wire.WriteError!void {
    var w = wire.Writer.init(gpa, buf);
    const arr = try w.beginArray(8);
    try writeDictSS(&w, "service", attrs.service);
    try writeDictSS(&w, "username", attrs.username);
    try writeDictSS(&w, "xdg:schema", schema_name);
    w.endArray(arr);
}

/// Marshal a SearchItems query. Do not include `xdg:schema`: Python keyring's
/// SecretStorage backend writes only `service`, `username`, and `application`.
pub fn writeSearchAttributes(gpa: Allocator, buf: *std.ArrayList(u8), attrs: Attributes) wire.WriteError!void {
    var w = wire.Writer.init(gpa, buf);
    const arr = try w.beginArray(8);
    try writeDictSS(&w, "service", attrs.service);
    try writeDictSS(&w, "username", attrs.username);
    w.endArray(arr);
}

fn writeDictSS(w: *wire.Writer, key: []const u8, value: []const u8) wire.WriteError!void {
    try w.alignStruct();
    try w.writeString(key);
    try w.writeString(value);
}

/// Marshal the `(a{sv}, (oayays), b)` body used by `Collection.CreateItem`.
///
/// Properties are emitted as a two-entry `a{sv}` dict with
/// `org.freedesktop.Secret.Item.Label` and
/// `org.freedesktop.Secret.Item.Attributes`. The secret is the standard
/// `(oayays)` tuple. For `.plain` cipher, `parameters` is empty and `value`
/// is the cleartext. For `.dh_ietf`, `parameters` is the 16-byte IV and
/// `value` is the AES-128-CBC + PKCS#7 ciphertext.
pub fn writeCreateItemBody(
    gpa: Allocator,
    buf: *std.ArrayList(u8),
    label: []const u8,
    attrs: Attributes,
    session_path: []const u8,
    value: []const u8,
    replace: bool,
    cipher: SessionCipher,
) WriteCreateItemError!void {
    var w = wire.Writer.init(gpa, buf);

    // a{sv} properties
    const props = try w.beginArray(8);

    try w.alignStruct();
    try w.writeString("org.freedesktop.Secret.Item.Label");
    try w.writeSignatureValue("s");
    try w.writeString(label);

    try w.alignStruct();
    try w.writeString("org.freedesktop.Secret.Item.Attributes");
    try w.writeSignatureValue("a{ss}");
    {
        const inner = try w.beginArray(8);
        try writeDictSS(&w, "service", attrs.service);
        try writeDictSS(&w, "username", attrs.username);
        try writeDictSS(&w, "xdg:schema", schema_name);
        w.endArray(inner);
    }

    w.endArray(props);

    // (oayays) secret
    try w.alignStruct();
    try w.writeObjectPath(session_path);

    switch (cipher) {
        .plain => {
            // Empty parameters, cleartext value.
            {
                const params = try w.beginArray(1);
                w.endArray(params);
            }
            {
                const bytes = try w.beginArray(1);
                try w.writeBytes(value);
                w.endArray(bytes);
            }
        },
        .dh_ietf => |cfg| {
            // parameters = IV (16 bytes); value = CBC-PKCS#7(value).
            {
                const params = try w.beginArray(1);
                try w.writeBytes(&cfg.iv);
                w.endArray(params);
            }
            const ct = try aes_cbc.encrypt(gpa, cfg.key, cfg.iv, value);
            defer gpa.free(ct);
            {
                const bytes = try w.beginArray(1);
                try w.writeBytes(ct);
                w.endArray(bytes);
            }
        },
    }

    try w.writeString("text/plain");

    // b replace
    try w.writeBool(replace);
}

/// Read the `(oayays)` secret returned by `Item.GetSecret`. The returned
/// slices borrow from `body`.
pub const ReadSecretError = wire.ReadError;

pub const Secret = struct {
    session: []const u8,
    parameters: []const u8,
    value: []const u8,
    content_type: []const u8,
};

pub fn readSecret(body: []const u8) ReadSecretError!Secret {
    var r = wire.Reader.init(body);
    try r.alignStruct();
    const session = try r.readObjectPath();
    const params_arr = try r.beginArray(1);
    const params = try r.readBytes(params_arr.end - r.pos);
    const value_arr = try r.beginArray(1);
    const value = try r.readBytes(value_arr.end - r.pos);
    const content_type = try r.readString();
    return .{
        .session = session,
        .parameters = params,
        .value = value,
        .content_type = content_type,
    };
}

/// Convert a parsed `Secret` into cleartext bytes. Caller owns the returned
/// slice. For `.plain`, the value is duplicated; for `.dh_ietf`, the
/// daemon-supplied `parameters` is interpreted as the CBC IV and the value
/// is decrypted in place.
pub fn decryptSecret(
    gpa: Allocator,
    secret: Secret,
    cipher: SessionCipher,
) DecryptSecretError![]u8 {
    switch (cipher) {
        .plain => return try gpa.dupe(u8, secret.value),
        .dh_ietf => |cfg| {
            if (secret.parameters.len != aes_cbc.block_length) return error.InvalidParameters;
            var iv: [aes_cbc.block_length]u8 = undefined;
            @memcpy(&iv, secret.parameters);
            return try aes_cbc.decrypt(gpa, cfg.key, iv, secret.value);
        },
    }
}

test "writeAttributes produces three dict entries" {
    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(std.testing.allocator);
    try writeAttributes(std.testing.allocator, &buf, .{
        .service = "svc",
        .username = "user",
    });

    // Parse it back: outer a{ss} with three string-pair entries.
    var r = wire.Reader.init(buf.items);
    const arr = try r.beginArray(8);
    var got: [3]struct { k: []const u8, v: []const u8 } = undefined;
    var i: usize = 0;
    while (r.arrayHasMore(arr)) : (i += 1) {
        try r.alignStruct();
        got[i].k = try r.readString();
        got[i].v = try r.readString();
    }
    try std.testing.expectEqual(@as(usize, 3), i);
    try std.testing.expectEqualStrings("service", got[0].k);
    try std.testing.expectEqualStrings("svc", got[0].v);
    try std.testing.expectEqualStrings("username", got[1].k);
    try std.testing.expectEqualStrings("user", got[1].v);
    try std.testing.expectEqualStrings("xdg:schema", got[2].k);
    try std.testing.expectEqualStrings(schema_name, got[2].v);
}

test "writeSearchAttributes omits schema for Python keyring compatibility" {
    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(std.testing.allocator);
    try writeSearchAttributes(std.testing.allocator, &buf, .{
        .service = "svc",
        .username = "user",
    });

    var r = wire.Reader.init(buf.items);
    const arr = try r.beginArray(8);
    var got: [2]struct { k: []const u8, v: []const u8 } = undefined;
    var i: usize = 0;
    while (r.arrayHasMore(arr)) : (i += 1) {
        try r.alignStruct();
        got[i].k = try r.readString();
        got[i].v = try r.readString();
    }
    try std.testing.expectEqual(@as(usize, 2), i);
    try std.testing.expectEqualStrings("service", got[0].k);
    try std.testing.expectEqualStrings("svc", got[0].v);
    try std.testing.expectEqualStrings("username", got[1].k);
    try std.testing.expectEqualStrings("user", got[1].v);
}

test "writeCreateItemBody round-trips through the parser" {
    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(std.testing.allocator);
    try writeCreateItemBody(
        std.testing.allocator,
        &buf,
        "svc/user",
        .{ .service = "svc", .username = "user" },
        "/org/freedesktop/secrets/session/s1",
        "the-secret",
        true,
        .plain,
    );

    var r = wire.Reader.init(buf.items);

    // a{sv} props
    const props = try r.beginArray(8);
    var label_seen: []const u8 = "";
    var attrs_inner_count: usize = 0;
    while (r.arrayHasMore(props)) {
        try r.alignStruct();
        const key = try r.readString();
        const sig = try r.readSignatureValue();
        if (std.mem.eql(u8, sig, "s")) {
            const v = try r.readString();
            if (std.mem.endsWith(u8, key, "Label")) label_seen = v;
        } else if (std.mem.eql(u8, sig, "a{ss}")) {
            const arr = try r.beginArray(8);
            while (r.arrayHasMore(arr)) {
                try r.alignStruct();
                _ = try r.readString();
                _ = try r.readString();
                attrs_inner_count += 1;
            }
        }
    }
    try std.testing.expectEqualStrings("svc/user", label_seen);
    try std.testing.expectEqual(@as(usize, 3), attrs_inner_count);

    // (oayays)
    try r.alignStruct();
    const session = try r.readObjectPath();
    try std.testing.expectEqualStrings("/org/freedesktop/secrets/session/s1", session);
    const params = try r.beginArray(1);
    try std.testing.expectEqual(@as(usize, 0), params.end - r.pos);
    r.pos = params.end;
    const valbytes = try r.beginArray(1);
    const value = try r.readBytes(valbytes.end - r.pos);
    try std.testing.expectEqualStrings("the-secret", value);
    const ct = try r.readString();
    try std.testing.expectEqualStrings("text/plain", ct);

    // b replace
    try std.testing.expectEqual(true, try r.readBool());
}

test "readSecret extracts value bytes" {
    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(std.testing.allocator);
    try writeCreateItemBody(
        std.testing.allocator,
        &buf,
        "label",
        .{ .service = "s", .username = "u" },
        "/sess",
        "abcd",
        false,
        .plain,
    );
    // The (oayays) starts at the 8-byte alignment after the a{sv}; reuse the
    // parsed body offset by walking the parser as a black box.
    var r = wire.Reader.init(buf.items);
    const props = try r.beginArray(8);
    r.pos = props.end;
    try r.alignStruct();
    const secret = try readSecret(buf.items[r.pos..]);
    try std.testing.expectEqualStrings("abcd", secret.value);
    try std.testing.expectEqualStrings("text/plain", secret.content_type);

    // decryptSecret on a .plain cipher dupes the value.
    const plain = try decryptSecret(std.testing.allocator, secret, .plain);
    defer std.testing.allocator.free(plain);
    try std.testing.expectEqualStrings("abcd", plain);
}

test "writeCreateItemBody + decryptSecret round-trip under .dh_ietf" {
    const cipher: SessionCipher = .{ .dh_ietf = .{
        .key = @splat(0x42),
        .iv = @splat(0x37),
    } };

    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(std.testing.allocator);
    try writeCreateItemBody(
        std.testing.allocator,
        &buf,
        "label",
        .{ .service = "s", .username = "u" },
        "/sess",
        "the-secret",
        false,
        cipher,
    );

    var r = wire.Reader.init(buf.items);
    const props = try r.beginArray(8);
    r.pos = props.end;
    try r.alignStruct();
    const secret = try readSecret(buf.items[r.pos..]);

    // parameters carries the IV exactly; value is the ciphertext.
    try std.testing.expectEqual(@as(usize, 16), secret.parameters.len);
    try std.testing.expectEqual(@as(u8, 0x37), secret.parameters[0]);
    try std.testing.expect(!std.mem.eql(u8, secret.value, "the-secret"));
    try std.testing.expectEqual(@as(usize, 16), secret.value.len); // pkcs7 pads to 16

    const plain = try decryptSecret(std.testing.allocator, secret, cipher);
    defer std.testing.allocator.free(plain);
    try std.testing.expectEqualStrings("the-secret", plain);
}

test "decryptSecret rejects wrong-length parameters under .dh_ietf" {
    const cipher: SessionCipher = .{ .dh_ietf = .{
        .key = @splat(0),
        .iv = @splat(0),
    } };
    const bogus: Secret = .{
        .session = "/sess",
        .parameters = "short",
        .value = &[_]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
        .content_type = "text/plain",
    };
    try std.testing.expectError(error.InvalidParameters, decryptSecret(std.testing.allocator, bogus, cipher));
}
