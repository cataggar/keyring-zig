//! High-level Secret Service operations used by `keyring-linux.zig`.
//!
//! Each operation opens (or reuses) a session, looks up / writes /
//! deletes one item in the default collection, and returns through the
//! normalized error set. The session may be `plain` (cleartext on the
//! AF_UNIX bus) or `dh_ietf` (AES-128-CBC + PKCS#7 with a key derived
//! from a 1024-bit DH exchange). The transport is selected at compile
//! time via the `-Dsecret-service-transport=auto|plain|dh` build option,
//! with `dh` automatically falling back to `plain` if the daemon reports
//! `NotSupported`. Item attributes mirror what libsecret stores
//! (`service`, `username`, `xdg:schema = "org.freedesktop.Secret.Generic"`),
//! so values written by the libsecret backend remain readable here and
//! vice versa.

const std = @import("std");
const builtin = @import("builtin");
const Allocator = std.mem.Allocator;
const dbus = @import("dbus");
const wire = dbus.wire;
const connection = dbus.connection;
const build_options = @import("build_options");

const encoding = @import("encoding.zig");
const session = @import("session.zig");
const prompt = @import("prompt.zig");
const aes_cbc = @import("aes_cbc.zig");

comptime {
    if (builtin.os.tag != .linux) @compileError("secret_service.client requires Linux");
}

pub const Error = error{
    EntryNotFound,
    NoStorageAccess,
    Locked,
    PlatformFailure,
    OutOfMemory,
    BufferTooSmall,
};

pub const Client = struct {
    gpa: Allocator,
    conn: connection.Connection,
    session_path: []u8,
    /// Session AES-128 key when the negotiated transport is `dh_ietf`;
    /// `null` for `plain`.
    session_key: ?[aes_cbc.key_length]u8,

    pub fn deinit(self: *Client) void {
        self.gpa.free(self.session_path);
        self.conn.deinit();
    }

    fn cipherFor(self: Client, iv: [aes_cbc.block_length]u8) encoding.SessionCipher {
        return if (self.session_key) |k|
            .{ .dh_ietf = .{ .key = k, .iv = iv } }
        else
            .plain;
    }

    fn readCipher(self: Client) encoding.SessionCipher {
        // For reads the daemon supplies the IV in `parameters`; pass a
        // zero placeholder here.
        return if (self.session_key) |k|
            .{ .dh_ietf = .{ .key = k, .iv = @splat(0) } }
        else
            .plain;
    }
};

pub fn open(gpa: Allocator) Error!Client {
    var conn = connection.connectSession(gpa) catch return Error.NoStorageAccess;
    errdefer conn.deinit();

    const want = pickTransport();
    const result = openWithFallback(&conn, want, gpa) catch return Error.PlatformFailure;
    return .{
        .gpa = gpa,
        .conn = conn,
        .session_path = result.path,
        .session_key = result.key,
    };
}

/// Try the requested transport; on `dh_ietf` `NotSupported`, retry with
/// `plain` so the keyring stays usable against daemons that only speak
/// the cleartext algorithm.
fn openWithFallback(
    conn: *connection.Connection,
    transport: session.Transport,
    out_gpa: Allocator,
) session.Error!session.OpenResult {
    if (session.openSession(conn, transport, out_gpa)) |r| {
        return r;
    } else |err| switch (err) {
        error.TransportNotSupported => {
            if (transport == .plain) return err;
            return session.openSession(conn, .plain, out_gpa);
        },
        else => return err,
    }
}

fn pickTransport() session.Transport {
    // The `KEYRING_TEST_TRANSPORT` env var lets the integration tests
    // exercise the `dh_ietf` path without rebuilding with a custom
    // `-Dsecret-service-transport`. It is intentionally undocumented for
    // end users.
    if (envEquals("KEYRING_TEST_TRANSPORT", "dh")) return .dh_ietf;
    if (envEquals("KEYRING_TEST_TRANSPORT", "plain")) return .plain;
    return switch (build_options.secret_service_transport) {
        .auto, .plain => .plain,
        .dh => .dh_ietf,
    };
}

fn envEquals(name: []const u8, expected: []const u8) bool {
    var i: usize = 0;
    while (std.c.environ[i]) |entry| : (i += 1) {
        const item = std.mem.span(entry);
        if (item.len > name.len and item[name.len] == '=' and std.mem.eql(u8, item[0..name.len], name)) {
            const value = item[name.len + 1 ..];
            return std.mem.eql(u8, value, expected);
        }
    }
    return false;
}

/// Look up the value for `(service, key)`. Returns `EntryNotFound` when no
/// item matches. Locked items are unlocked transparently via the Secret
/// Service prompt; if the user dismisses the prompt the call returns
/// `error.Locked`.
pub fn get(client: *Client, service: []const u8, key: []const u8, out_gpa: Allocator) Error![]u8 {
    const found = try searchItem(client, service, key);
    const item_path = switch (found) {
        .unlocked => |p| p,
        .locked => |p| blk: {
            try unlock(client, p);
            break :blk p;
        },
        .none => return Error.EntryNotFound,
    };
    defer client.gpa.free(item_path);

    var body: std.ArrayList(u8) = .empty;
    defer body.deinit(client.gpa);
    var w = wire.Writer.init(client.gpa, &body);
    try w.writeObjectPath(client.session_path);

    var reply = connection.call(&client.conn, .{
        .destination = session.service_destination,
        .path = item_path,
        .interface = "org.freedesktop.Secret.Item",
        .member = "GetSecret",
        .signature = "o",
        .body = body.items,
    }) catch return Error.PlatformFailure;
    defer reply.deinit();
    if (reply.err) |_| return Error.PlatformFailure;

    const secret = encoding.readSecret(reply.body) catch return Error.PlatformFailure;
    const plaintext = encoding.decryptSecret(client.gpa, secret, client.readCipher()) catch
        return Error.PlatformFailure;
    defer client.gpa.free(plaintext);
    return try out_gpa.dupe(u8, plaintext);
}

pub fn set(client: *Client, service: []const u8, key: []const u8, value: []const u8) Error!void {
    const collection = try defaultCollection(client);
    defer client.gpa.free(collection);

    var label_buf: std.ArrayList(u8) = .empty;
    defer label_buf.deinit(client.gpa);
    try label_buf.appendSlice(client.gpa, service);
    try label_buf.append(client.gpa, '/');
    try label_buf.appendSlice(client.gpa, key);

    var iv: [aes_cbc.block_length]u8 = undefined;
    if (client.session_key != null) randomBytes(&iv);

    var body: std.ArrayList(u8) = .empty;
    defer body.deinit(client.gpa);
    encoding.writeCreateItemBody(
        client.gpa,
        &body,
        label_buf.items,
        .{ .service = service, .username = key },
        client.session_path,
        value,
        true,
        client.cipherFor(iv),
    ) catch return Error.PlatformFailure;

    var attempt: u8 = 0;
    while (true) : (attempt += 1) {
        var reply = connection.call(&client.conn, .{
            .destination = session.service_destination,
            .path = collection,
            .interface = "org.freedesktop.Secret.Collection",
            .member = "CreateItem",
            .signature = "a{sv}(oayays)b",
            .body = body.items,
        }) catch return Error.PlatformFailure;
        defer reply.deinit();
        if (reply.err) |e| {
            if (attempt == 0 and std.mem.endsWith(u8, e.name, ".IsLocked")) {
                try unlock(client, collection);
                continue;
            }
            return Error.PlatformFailure;
        }

        var r = wire.Reader.init(reply.body);
        _ = r.readObjectPath() catch return Error.PlatformFailure;
        const prompt_path = r.readObjectPath() catch return Error.PlatformFailure;
        if (!std.mem.eql(u8, prompt_path, "/")) {
            prompt.run(&client.conn, prompt_path) catch |e| return switch (e) {
                error.Locked => Error.Locked,
                error.OutOfMemory => Error.OutOfMemory,
                else => Error.PlatformFailure,
            };
        }
        return;
    }
}

fn randomBytes(buf: []u8) void {
    session.secureRandom(buf);
}

pub fn delete(client: *Client, service: []const u8, key: []const u8) Error!void {
    const found = try searchItem(client, service, key);
    const item_path = switch (found) {
        .unlocked => |p| p,
        .locked => |p| blk: {
            try unlock(client, p);
            break :blk p;
        },
        .none => return Error.EntryNotFound,
    };
    defer client.gpa.free(item_path);

    var reply = connection.call(&client.conn, .{
        .destination = session.service_destination,
        .path = item_path,
        .interface = "org.freedesktop.Secret.Item",
        .member = "Delete",
        .signature = null,
        .body = &[_]u8{},
    }) catch return Error.PlatformFailure;
    defer reply.deinit();
    if (reply.err) |_| return Error.PlatformFailure;

    var r = wire.Reader.init(reply.body);
    const prompt_path = r.readObjectPath() catch return Error.PlatformFailure;
    if (!std.mem.eql(u8, prompt_path, "/")) {
        prompt.run(&client.conn, prompt_path) catch |e| return switch (e) {
            error.Locked => Error.Locked,
            error.OutOfMemory => Error.OutOfMemory,
            else => Error.PlatformFailure,
        };
    }
}

const Found = union(enum) {
    unlocked: []u8,
    locked: []u8,
    none,
};

fn searchItem(client: *Client, service: []const u8, key: []const u8) Error!Found {
    var body: std.ArrayList(u8) = .empty;
    defer body.deinit(client.gpa);
    try encoding.writeAttributes(client.gpa, &body, .{ .service = service, .username = key });

    var reply = connection.call(&client.conn, .{
        .destination = session.service_destination,
        .path = session.service_path,
        .interface = session.service_interface,
        .member = "SearchItems",
        .signature = "a{ss}",
        .body = body.items,
    }) catch return Error.PlatformFailure;
    defer reply.deinit();
    if (reply.err) |_| return Error.PlatformFailure;

    var r = wire.Reader.init(reply.body);
    const unlocked = r.beginArray(4) catch return Error.PlatformFailure;
    if (r.arrayHasMore(unlocked)) {
        const path = r.readObjectPath() catch return Error.PlatformFailure;
        return Found{ .unlocked = try client.gpa.dupe(u8, path) };
    }
    r.pos = unlocked.end;
    const locked = r.beginArray(4) catch return Error.PlatformFailure;
    if (r.arrayHasMore(locked)) {
        const path = r.readObjectPath() catch return Error.PlatformFailure;
        return Found{ .locked = try client.gpa.dupe(u8, path) };
    }
    return Found{ .none = {} };
}

/// Unlock a single object (item or collection) via `Service.Unlock`. If the
/// daemon needs user confirmation, the prompt is driven through to
/// completion; a dismissed prompt surfaces as `error.Locked`.
fn unlock(client: *Client, object_path: []const u8) Error!void {
    var body: std.ArrayList(u8) = .empty;
    defer body.deinit(client.gpa);
    var w = wire.Writer.init(client.gpa, &body);
    const arr = try w.beginArray(4);
    try w.writeObjectPath(object_path);
    w.endArray(arr);

    var reply = connection.call(&client.conn, .{
        .destination = session.service_destination,
        .path = session.service_path,
        .interface = session.service_interface,
        .member = "Unlock",
        .signature = "ao",
        .body = body.items,
    }) catch return Error.PlatformFailure;
    defer reply.deinit();
    if (reply.err) |_| return Error.PlatformFailure;

    var r = wire.Reader.init(reply.body);
    const unlocked_arr = r.beginArray(4) catch return Error.PlatformFailure;
    // Skip the immediately-unlocked array; we only care whether a prompt is
    // attached.
    r.pos = unlocked_arr.end;
    const prompt_path = r.readObjectPath() catch return Error.PlatformFailure;
    if (!std.mem.eql(u8, prompt_path, "/")) {
        prompt.run(&client.conn, prompt_path) catch |e| return switch (e) {
            error.Locked => Error.Locked,
            error.OutOfMemory => Error.OutOfMemory,
            else => Error.PlatformFailure,
        };
    }
}

fn defaultCollection(client: *Client) Error![]u8 {
    var body: std.ArrayList(u8) = .empty;
    defer body.deinit(client.gpa);
    var w = wire.Writer.init(client.gpa, &body);
    try w.writeString("default");

    var reply = connection.call(&client.conn, .{
        .destination = session.service_destination,
        .path = session.service_path,
        .interface = session.service_interface,
        .member = "ReadAlias",
        .signature = "s",
        .body = body.items,
    }) catch return Error.PlatformFailure;
    defer reply.deinit();
    if (reply.err) |_| return Error.PlatformFailure;

    var r = wire.Reader.init(reply.body);
    const path = r.readObjectPath() catch return Error.PlatformFailure;
    if (std.mem.eql(u8, path, "/")) return Error.NoStorageAccess;
    return try client.gpa.dupe(u8, path);
}

fn serviceAvailable(gpa: Allocator) bool {
    var conn = connection.connectSession(gpa) catch return false;
    defer conn.deinit();

    var body: std.ArrayList(u8) = .empty;
    defer body.deinit(gpa);
    var w = wire.Writer.init(gpa, &body);
    w.writeString(session.service_destination) catch return false;

    var reply = connection.call(&conn, .{
        .destination = "org.freedesktop.DBus",
        .path = "/org/freedesktop/DBus",
        .interface = "org.freedesktop.DBus",
        .member = "NameHasOwner",
        .signature = "s",
        .body = body.items,
    }) catch return false;
    defer reply.deinit();
    if (reply.err != null) return false;

    var r = wire.Reader.init(reply.body);
    return r.readBool() catch false;
}

test "integration: set/get/delete round trip" {
    if (!serviceAvailable(std.testing.allocator)) return;

    var c = open(std.testing.allocator) catch return;
    defer c.deinit();

    const service = "keyring-zig-test-service";
    const key = "keyring-zig-test-key";
    const value = "keyring-zig-test-value";

    // Best effort: clear any pre-existing entry.
    delete(&c, service, key) catch {};

    try set(&c, service, key, value);
    defer delete(&c, service, key) catch {};

    const got = try get(&c, service, key, std.testing.allocator);
    defer std.testing.allocator.free(got);
    try std.testing.expectEqualStrings(value, got);
}

test "integration: get missing returns EntryNotFound" {
    if (!serviceAvailable(std.testing.allocator)) return;

    var c = open(std.testing.allocator) catch return;
    defer c.deinit();

    var buf: [16]u8 = undefined;
    _ = &buf;
    try std.testing.expectError(
        Error.EntryNotFound,
        get(&c, "keyring-zig-missing-svc", "keyring-zig-missing-key", std.testing.allocator),
    );
}
