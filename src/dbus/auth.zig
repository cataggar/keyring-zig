//! SASL EXTERNAL authentication handshake.
//!
//! After connecting the unix socket, the client must send a leading NUL byte
//! then run the very small SASL state machine: send `AUTH EXTERNAL <hex-uid>\r\n`,
//! await `OK <guid>\r\n`, then send `BEGIN\r\n`. We do not negotiate Unix FD
//! passing since the Secret Service does not use it.

const std = @import("std");

pub const Error = error{
    AuthRejected,
    AuthProtocol,
    AuthTruncated,
    OutOfMemory,
    WriteFailed,
    ReadFailed,
};

/// I/O abstraction so we can unit-test against in-memory streams.
pub const Stream = struct {
    context: *anyopaque,
    write_fn: *const fn (ctx: *anyopaque, bytes: []const u8) anyerror!void,
    read_fn: *const fn (ctx: *anyopaque, buf: []u8) anyerror!usize,

    fn write(self: Stream, bytes: []const u8) Error!void {
        self.write_fn(self.context, bytes) catch return Error.WriteFailed;
    }

    fn read(self: Stream, buf: []u8) Error!usize {
        return self.read_fn(self.context, buf) catch Error.ReadFailed;
    }
};

/// Run the handshake on `stream`. Caller must already have sent the leading
/// NUL byte (`connection.zig` does this immediately after `connect`).
pub fn authenticateExternal(gpa: std.mem.Allocator, stream: Stream, uid: u32) Error!void {
    var hex_buf: [16]u8 = undefined;
    const hex = uidToHex(uid, &hex_buf);

    var line: std.ArrayList(u8) = .empty;
    defer line.deinit(gpa);
    try line.appendSlice(gpa, "AUTH EXTERNAL ");
    try line.appendSlice(gpa, hex);
    try line.appendSlice(gpa, "\r\n");
    try stream.write(line.items);

    var reply_buf: [256]u8 = undefined;
    const reply = try readLine(stream, &reply_buf);
    if (!std.mem.startsWith(u8, reply, "OK ")) {
        if (std.mem.startsWith(u8, reply, "REJECTED")) return Error.AuthRejected;
        return Error.AuthProtocol;
    }

    try stream.write("BEGIN\r\n");
}

fn uidToHex(uid: u32, out: []u8) []const u8 {
    var dec_buf: [16]u8 = undefined;
    const dec = std.fmt.bufPrint(&dec_buf, "{d}", .{uid}) catch unreachable;
    var i: usize = 0;
    for (dec) |c| {
        const hi: u4 = @intCast(c >> 4);
        const lo: u4 = @intCast(c & 0x0F);
        out[i] = std.fmt.digitToChar(hi, .lower);
        out[i + 1] = std.fmt.digitToChar(lo, .lower);
        i += 2;
    }
    return out[0..i];
}

fn readLine(stream: Stream, buf: []u8) Error![]const u8 {
    var len: usize = 0;
    while (true) {
        if (len >= buf.len) return Error.AuthProtocol;
        const n = try stream.read(buf[len .. len + 1]);
        if (n == 0) return Error.AuthTruncated;
        len += 1;
        if (len >= 2 and buf[len - 2] == '\r' and buf[len - 1] == '\n') {
            return buf[0 .. len - 2];
        }
    }
}

/// In-memory test stream: writes go into `out`, reads pull from `in`.
const TestStream = struct {
    in: []const u8,
    in_pos: usize = 0,
    out: *std.ArrayList(u8),
    gpa: std.mem.Allocator,

    fn write(ctx: *anyopaque, bytes: []const u8) anyerror!void {
        const self: *TestStream = @ptrCast(@alignCast(ctx));
        try self.out.appendSlice(self.gpa, bytes);
    }

    fn read(ctx: *anyopaque, buf: []u8) anyerror!usize {
        const self: *TestStream = @ptrCast(@alignCast(ctx));
        const remaining = self.in.len - self.in_pos;
        const n = @min(buf.len, remaining);
        @memcpy(buf[0..n], self.in[self.in_pos .. self.in_pos + n]);
        self.in_pos += n;
        return n;
    }
};

test "authenticateExternal emits AUTH and BEGIN" {
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(std.testing.allocator);
    var ts = TestStream{
        .in = "OK 1234567890abcdef\r\n",
        .out = &out,
        .gpa = std.testing.allocator,
    };
    const stream = Stream{
        .context = &ts,
        .write_fn = TestStream.write,
        .read_fn = TestStream.read,
    };
    try authenticateExternal(std.testing.allocator, stream, 1000);
    try std.testing.expectEqualStrings(
        "AUTH EXTERNAL 31303030\r\nBEGIN\r\n",
        out.items,
    );
}

test "authenticateExternal rejects REJECTED" {
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(std.testing.allocator);
    var ts = TestStream{
        .in = "REJECTED EXTERNAL\r\n",
        .out = &out,
        .gpa = std.testing.allocator,
    };
    const stream = Stream{
        .context = &ts,
        .write_fn = TestStream.write,
        .read_fn = TestStream.read,
    };
    try std.testing.expectError(Error.AuthRejected, authenticateExternal(std.testing.allocator, stream, 1000));
}

test "uidToHex encodes ASCII digits" {
    var buf: [16]u8 = undefined;
    try std.testing.expectEqualStrings("31303030", uidToHex(1000, &buf));
    try std.testing.expectEqualStrings("30", uidToHex(0, &buf));
}
