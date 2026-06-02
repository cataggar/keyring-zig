//! Synchronous D-Bus client connection over `AF_UNIX`.
//!
//! Uses `std.os.linux` syscalls directly so this module has no dependency on
//! libsecret, glib, or the higher-level `std.Io` net abstraction. Linux only.
//!
//! `connectSession` opens the session bus, performs the SASL EXTERNAL
//! handshake, calls `Hello()` to obtain a unique bus name, and is then ready
//! to send method calls via `call`. Replies are read off the socket until
//! the serial we are waiting for arrives; messages addressed to other serials
//! (signals, stale replies) are dropped.

const std = @import("std");
const builtin = @import("builtin");
const linux = std.os.linux;
const Allocator = std.mem.Allocator;

const address_mod = @import("address.zig");
const auth = @import("auth.zig");
const wire = @import("wire.zig");
const message = @import("message.zig");

comptime {
    if (builtin.os.tag != .linux) @compileError("D-Bus connection is Linux-only");
}

pub const Error = error{
    OutOfMemory,
    ConnectFailed,
    SocketFailed,
    WriteFailed,
    ReadFailed,
    AuthFailed,
    UnknownEndian,
    UnknownMessageType,
    Truncated,
    InvalidString,
    InvalidBool,
    InvalidObjectPath,
    InvalidSignature,
    MethodCallFailed,
    NoReply,
    PathTooLong,
};

/// A peer-reported `org.freedesktop.DBus.Error.*` reply.
pub const DBusError = struct {
    name: []const u8,
    message_text: []const u8,
};

pub const Reply = struct {
    arena: std.heap.ArenaAllocator,
    body: []const u8,
    signature: ?[]const u8,
    err: ?DBusError,

    pub fn deinit(self: *Reply) void {
        self.arena.deinit();
    }
};

pub const Connection = struct {
    gpa: Allocator,
    fd: linux.fd_t,
    next_serial: u32 = 1,
    unique_name: ?[]u8 = null,

    pub fn deinit(self: *Connection) void {
        if (self.unique_name) |n| self.gpa.free(n);
        _ = linux.close(self.fd);
    }
};

/// Open the session bus identified by `$DBUS_SESSION_BUS_ADDRESS` (or the
/// fallback `$XDG_RUNTIME_DIR/bus`), run SASL EXTERNAL, and send `Hello`.
pub fn connectSession(gpa: Allocator) Error!Connection {
    var addr_scratch: [4096]u8 = undefined;
    var runtime_scratch: [4096]u8 = undefined;

    const bus_addr = getEnv(&addr_scratch, "DBUS_SESSION_BUS_ADDRESS");
    const runtime_dir = getEnv(&runtime_scratch, "XDG_RUNTIME_DIR");

    var owned_addr: ?[]u8 = null;
    defer if (owned_addr) |o| gpa.free(o);
    const addr_str = bus_addr orelse blk: {
        const rt = runtime_dir orelse return Error.ConnectFailed;
        const joined = std.fmt.allocPrint(gpa, "unix:path={s}/bus", .{rt}) catch return Error.OutOfMemory;
        owned_addr = joined;
        break :blk joined;
    };

    const parsed = address_mod.parse(gpa, addr_str, runtime_dir) catch return Error.ConnectFailed;
    defer address_mod.free(gpa, parsed);

    return openAndHandshake(gpa, parsed);
}

fn openAndHandshake(gpa: Allocator, addr: address_mod.Address) Error!Connection {
    const fd = try openUnixSocket();
    errdefer _ = linux.close(fd);

    switch (addr) {
        .path => |p| try connectPath(fd, p),
        .abstract => |a| try connectAbstract(fd, a),
    }

    try writeAll(fd, &[_]u8{0});

    var fd_ctx = FdStream{ .fd = fd };
    const stream = auth.Stream{
        .context = &fd_ctx,
        .write_fn = FdStream.write,
        .read_fn = FdStream.read,
    };
    const uid: u32 = @intCast(linux.getuid());
    auth.authenticateExternal(gpa, stream, uid) catch return Error.AuthFailed;

    var conn: Connection = .{ .gpa = gpa, .fd = fd };
    errdefer conn.deinit();

    var hello = try call(&conn, .{
        .destination = "org.freedesktop.DBus",
        .path = "/org/freedesktop/DBus",
        .interface = "org.freedesktop.DBus",
        .member = "Hello",
        .signature = null,
        .body = &[_]u8{},
    });
    defer hello.deinit();
    if (hello.err) |_| return Error.MethodCallFailed;

    var r = wire.Reader.init(hello.body);
    const name = r.readString() catch return Error.ReadFailed;
    conn.unique_name = try gpa.dupe(u8, name);
    return conn;
}

fn openUnixSocket() Error!linux.fd_t {
    const ret = linux.socket(linux.AF.UNIX, linux.SOCK.STREAM | linux.SOCK.CLOEXEC, 0);
    switch (linux.errno(ret)) {
        .SUCCESS => return @intCast(ret),
        else => return Error.SocketFailed,
    }
}

fn connectPath(fd: linux.fd_t, path: []const u8) Error!void {
    var sa: linux.sockaddr.un = .{ .family = linux.AF.UNIX, .path = undefined };
    if (path.len >= sa.path.len) return Error.PathTooLong;
    @memset(&sa.path, 0);
    @memcpy(sa.path[0..path.len], path);
    const ret = linux.connect(fd, @ptrCast(&sa), @sizeOf(linux.sockaddr.un));
    switch (linux.errno(ret)) {
        .SUCCESS => return,
        else => return Error.ConnectFailed,
    }
}

fn connectAbstract(fd: linux.fd_t, name: []const u8) Error!void {
    var sa: linux.sockaddr.un = .{ .family = linux.AF.UNIX, .path = undefined };
    if (name.len + 1 > sa.path.len) return Error.PathTooLong;
    @memset(&sa.path, 0);
    sa.path[0] = 0;
    @memcpy(sa.path[1 .. 1 + name.len], name);
    const len: linux.socklen_t = @intCast(@offsetOf(linux.sockaddr.un, "path") + 1 + name.len);
    const ret = linux.connect(fd, @ptrCast(&sa), len);
    switch (linux.errno(ret)) {
        .SUCCESS => return,
        else => return Error.ConnectFailed,
    }
}

pub const CallRequest = struct {
    destination: []const u8,
    path: []const u8,
    interface: []const u8,
    member: []const u8,
    signature: ?[]const u8,
    body: []const u8,
};

/// Send a method call and block until the matching reply (or error) arrives.
pub fn call(conn: *Connection, req: CallRequest) Error!Reply {
    const serial = conn.next_serial;
    conn.next_serial += 1;

    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(conn.gpa);
    message.serialize(conn.gpa, &out, .{
        .msg_type = .method_call,
        .serial = serial,
        .destination = req.destination,
        .path = req.path,
        .interface = req.interface,
        .member = req.member,
        .signature = req.signature,
    }, req.body) catch return Error.OutOfMemory;

    try writeAll(conn.fd, out.items);

    return readReplyFor(conn, serial);
}

fn readReplyFor(conn: *Connection, serial: u32) Error!Reply {
    while (true) {
        var arena = std.heap.ArenaAllocator.init(conn.gpa);
        errdefer arena.deinit();
        const aa = arena.allocator();

        var prefix: [message.min_header_bytes]u8 = undefined;
        try readExact(conn.fd, &prefix);

        const total = message.totalLength(prefix) catch return Error.Truncated;

        const bytes = aa.alloc(u8, total) catch return Error.OutOfMemory;
        @memcpy(bytes[0..message.min_header_bytes], &prefix);
        try readExact(conn.fd, bytes[message.min_header_bytes..]);

        const parsed = message.parse(bytes) catch |e| return mapParseError(e);

        if (parsed.header.reply_serial == null or parsed.header.reply_serial.? != serial) {
            arena.deinit();
            continue;
        }

        var err_payload: ?DBusError = null;
        if (parsed.header.msg_type == .error_reply) {
            var r = wire.Reader.init(parsed.body);
            const msg = if (parsed.header.signature != null and
                std.mem.startsWith(u8, parsed.header.signature.?, "s"))
                (r.readString() catch "")
            else
                "";
            err_payload = .{
                .name = parsed.header.error_name orelse "",
                .message_text = msg,
            };
        }

        return .{
            .arena = arena,
            .body = parsed.body,
            .signature = parsed.header.signature,
            .err = err_payload,
        };
    }
}

fn mapParseError(e: message.ParseError) Error {
    return switch (e) {
        error.UnknownEndian => Error.UnknownEndian,
        error.UnknownMessageType => Error.UnknownMessageType,
        error.Truncated => Error.Truncated,
        error.InvalidString => Error.InvalidString,
        error.InvalidBool => Error.InvalidBool,
        error.InvalidObjectPath => Error.InvalidObjectPath,
        error.InvalidSignature => Error.InvalidSignature,
    };
}

fn writeAll(fd: linux.fd_t, bytes: []const u8) Error!void {
    var off: usize = 0;
    while (off < bytes.len) {
        const ret = linux.write(fd, bytes[off..].ptr, bytes.len - off);
        switch (linux.errno(ret)) {
            .SUCCESS => {
                if (ret == 0) return Error.WriteFailed;
                off += ret;
            },
            .INTR => continue,
            else => return Error.WriteFailed,
        }
    }
}

fn readExact(fd: linux.fd_t, buf: []u8) Error!void {
    var off: usize = 0;
    while (off < buf.len) {
        const ret = linux.read(fd, buf[off..].ptr, buf.len - off);
        switch (linux.errno(ret)) {
            .SUCCESS => {
                if (ret == 0) return Error.ReadFailed;
                off += ret;
            },
            .INTR => continue,
            else => return Error.ReadFailed,
        }
    }
}

/// Look up an environment variable from the process's environ vector.
/// Returns a slice into `scratch`, or null if not found.
fn getEnv(scratch: []u8, name: []const u8) ?[]const u8 {
    var i: usize = 0;
    while (std.c.environ[i]) |entry| : (i += 1) {
        const item = std.mem.span(entry);
        if (item.len > name.len and item[name.len] == '=' and std.mem.eql(u8, item[0..name.len], name)) {
            const value = item[name.len + 1 ..];
            if (value.len > scratch.len) return null;
            @memcpy(scratch[0..value.len], value);
            return scratch[0..value.len];
        }
    }
    return null;
}

const FdStream = struct {
    fd: linux.fd_t,

    fn write(ctx: *anyopaque, bytes: []const u8) anyerror!void {
        const self: *FdStream = @ptrCast(@alignCast(ctx));
        try writeAll(self.fd, bytes);
    }

    fn read(ctx: *anyopaque, buf: []u8) anyerror!usize {
        const self: *FdStream = @ptrCast(@alignCast(ctx));
        while (true) {
            const ret = linux.read(self.fd, buf.ptr, buf.len);
            switch (linux.errno(ret)) {
                .SUCCESS => return ret,
                .INTR => continue,
                else => return error.ReadFailed,
            }
        }
    }
};

test "integration: connect to session bus and get unique name" {
    var scratch: [4096]u8 = undefined;
    const addr = getEnv(&scratch, "DBUS_SESSION_BUS_ADDRESS") orelse return;
    if (!std.mem.startsWith(u8, addr, "unix:")) return;
    if (!socketReachable(addr)) return;

    var conn = try connectSession(std.testing.allocator);
    defer conn.deinit();

    try std.testing.expect(conn.unique_name != null);
    try std.testing.expect(std.mem.startsWith(u8, conn.unique_name.?, ":"));
}

test "integration: ListNames returns the bus driver" {
    var scratch: [4096]u8 = undefined;
    const addr = getEnv(&scratch, "DBUS_SESSION_BUS_ADDRESS") orelse return;
    if (!socketReachable(addr)) return;

    var conn = try connectSession(std.testing.allocator);
    defer conn.deinit();

    var reply = try call(&conn, .{
        .destination = "org.freedesktop.DBus",
        .path = "/org/freedesktop/DBus",
        .interface = "org.freedesktop.DBus",
        .member = "ListNames",
        .signature = null,
        .body = &[_]u8{},
    });
    defer reply.deinit();

    try std.testing.expect(reply.err == null);
    try std.testing.expectEqualStrings("as", reply.signature.?);

    var r = wire.Reader.init(reply.body);
    const arr = try r.beginArray(4);
    var saw_driver = false;
    while (r.arrayHasMore(arr)) {
        const name = try r.readString();
        if (std.mem.eql(u8, name, "org.freedesktop.DBus")) saw_driver = true;
    }
    try std.testing.expect(saw_driver);
}

fn socketReachable(addr: []const u8) bool {
    const idx = std.mem.indexOf(u8, addr, "path=") orelse return true;
    const start = idx + 5;
    const end = std.mem.indexOfScalarPos(u8, addr, start, ',') orelse addr.len;
    const path = addr[start..end];
    if (path.len == 0 or path.len >= 108) return false;
    const fd = openUnixSocket() catch return false;
    defer _ = linux.close(fd);
    connectPath(fd, path) catch return false;
    return true;
}
