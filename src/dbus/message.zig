//! D-Bus method-call / method-return / error / signal messages.
//!
//! The serializer writes little-endian only; the parser accepts both endians.
//! Body bytes are supplied by the caller already marshalled at the body's
//! 8-byte-aligned coordinate space.

const std = @import("std");
const Allocator = std.mem.Allocator;
const wire = @import("wire.zig");

pub const Endian = enum(u8) {
    little = 'l',
    big = 'B',
};

pub const MessageType = enum(u8) {
    invalid = 0,
    method_call = 1,
    method_return = 2,
    error_reply = 3,
    signal = 4,
};

pub const Flags = packed struct(u8) {
    no_reply_expected: bool = false,
    no_auto_start: bool = false,
    allow_interactive_authorization: bool = false,
    _reserved: u5 = 0,
};

pub const FieldCode = enum(u8) {
    invalid = 0,
    path = 1,
    interface = 2,
    member = 3,
    error_name = 4,
    reply_serial = 5,
    destination = 6,
    sender = 7,
    signature = 8,
    unix_fds = 9,
};

pub const Header = struct {
    msg_type: MessageType,
    flags: Flags = .{},
    serial: u32,
    path: ?[]const u8 = null,
    interface: ?[]const u8 = null,
    member: ?[]const u8 = null,
    error_name: ?[]const u8 = null,
    reply_serial: ?u32 = null,
    destination: ?[]const u8 = null,
    sender: ?[]const u8 = null,
    signature: ?[]const u8 = null,
};

pub const SerializeError = error{OutOfMemory};

/// Append a complete wire-format message (header + padding + body) to `out`.
pub fn serialize(gpa: Allocator, out: *std.ArrayList(u8), header: Header, body: []const u8) SerializeError!void {
    var w = wire.Writer.init(gpa, out);
    const message_start = out.items.len;

    try w.writeByte(@intFromEnum(Endian.little));
    try w.writeByte(@intFromEnum(header.msg_type));
    try w.writeByte(@as(u8, @bitCast(header.flags)));
    try w.writeByte(1); // protocol version
    try w.writeU32(@intCast(body.len));
    try w.writeU32(header.serial);

    const arr = try w.beginArray(8);

    if (header.path) |v| try writeField(&w, .path, "o", v);
    if (header.interface) |v| try writeField(&w, .interface, "s", v);
    if (header.member) |v| try writeField(&w, .member, "s", v);
    if (header.error_name) |v| try writeField(&w, .error_name, "s", v);
    if (header.reply_serial) |v| try writeFieldU32(&w, .reply_serial, v);
    if (header.destination) |v| try writeField(&w, .destination, "s", v);
    if (header.sender) |v| try writeField(&w, .sender, "s", v);
    if (header.signature) |v| try writeFieldSig(&w, .signature, v);

    w.endArray(arr);

    // Body is aligned to 8 bytes relative to message start.
    const cur = out.items.len - message_start;
    const target = std.mem.alignForward(usize, cur, 8);
    var i = cur;
    while (i < target) : (i += 1) try out.append(gpa, 0);

    try out.appendSlice(gpa, body);
}

fn writeField(w: *wire.Writer, code: FieldCode, sig: []const u8, value: []const u8) wire.WriteError!void {
    try w.alignStruct();
    try w.writeByte(@intFromEnum(code));
    try w.writeSignatureValue(sig);
    if (std.mem.eql(u8, sig, "o")) {
        try w.writeObjectPath(value);
    } else {
        try w.writeString(value);
    }
}

fn writeFieldU32(w: *wire.Writer, code: FieldCode, value: u32) wire.WriteError!void {
    try w.alignStruct();
    try w.writeByte(@intFromEnum(code));
    try w.writeSignatureValue("u");
    try w.writeU32(value);
}

fn writeFieldSig(w: *wire.Writer, code: FieldCode, value: []const u8) wire.WriteError!void {
    try w.alignStruct();
    try w.writeByte(@intFromEnum(code));
    try w.writeSignatureValue("g");
    try w.writeSignatureValue(value);
}

pub const ParseError = wire.ReadError || error{ UnknownEndian, UnknownMessageType };

pub const Parsed = struct {
    header: Header,
    body: []const u8,
    consumed: usize,
};

/// The minimum number of leading bytes required to know the total message
/// length. Header is 12 fixed bytes plus a 4-byte header-array length prefix.
pub const min_header_bytes: usize = 16;

/// Given the first `min_header_bytes` of a message, compute the total length
/// (header + padding + body) of that message. Caller can then read the rest.
pub fn totalLength(prefix: [min_header_bytes]u8) ParseError!usize {
    const endian: std.builtin.Endian = switch (prefix[0]) {
        'l' => .little,
        'B' => .big,
        else => return ParseError.UnknownEndian,
    };
    const body_len = std.mem.readInt(u32, prefix[4..8], endian);
    const header_array_len = std.mem.readInt(u32, prefix[12..16], endian);
    const after_array = min_header_bytes + header_array_len;
    const body_start = std.mem.alignForward(usize, after_array, 8);
    return body_start + body_len;
}

/// Parse a complete message from `bytes`. Returned slices borrow from `bytes`.
pub fn parse(bytes: []const u8) ParseError!Parsed {
    if (bytes.len < min_header_bytes) return ParseError.Truncated;
    var r = wire.Reader.init(bytes);

    const endian_byte = try r.readByte();
    r.endian = switch (endian_byte) {
        'l' => .little,
        'B' => .big,
        else => return ParseError.UnknownEndian,
    };
    const type_byte = try r.readByte();
    const msg_type: MessageType = switch (type_byte) {
        0 => .invalid,
        1 => .method_call,
        2 => .method_return,
        3 => .error_reply,
        4 => .signal,
        else => return ParseError.UnknownMessageType,
    };
    const flags_byte = try r.readByte();
    _ = try r.readByte(); // version
    const body_len = try r.readU32();
    const serial = try r.readU32();

    var header: Header = .{
        .msg_type = msg_type,
        .flags = @bitCast(flags_byte),
        .serial = serial,
    };

    const arr = try r.beginArray(8);
    while (r.arrayHasMore(arr)) {
        try r.alignStruct();
        const code_byte = try r.readByte();
        const sig = try r.readSignatureValue();
        switch (code_byte) {
            @intFromEnum(FieldCode.path) => header.path = try r.readObjectPath(),
            @intFromEnum(FieldCode.interface) => header.interface = try r.readString(),
            @intFromEnum(FieldCode.member) => header.member = try r.readString(),
            @intFromEnum(FieldCode.error_name) => header.error_name = try r.readString(),
            @intFromEnum(FieldCode.reply_serial) => header.reply_serial = try r.readU32(),
            @intFromEnum(FieldCode.destination) => header.destination = try r.readString(),
            @intFromEnum(FieldCode.sender) => header.sender = try r.readString(),
            @intFromEnum(FieldCode.signature) => header.signature = try r.readSignatureValue(),
            else => try skipVariantBody(&r, sig),
        }
    }

    try r.alignTo(8);
    if (r.pos + body_len > bytes.len) return ParseError.Truncated;
    const body = bytes[r.pos .. r.pos + body_len];
    return .{ .header = header, .body = body, .consumed = r.pos + body_len };
}

fn skipVariantBody(r: *wire.Reader, sig: []const u8) wire.ReadError!void {
    if (sig.len == 0) return;
    // We only ever encounter known field codes in practice; defensively skip
    // primitive types and any single string-like value.
    switch (sig[0]) {
        'y' => _ = try r.readByte(),
        'b', 'u', 'i' => _ = try r.readU32(),
        'n', 'q' => _ = try r.readU16(),
        'x', 't', 'd' => _ = try r.readU64(),
        's', 'o' => _ = try r.readString(),
        'g' => _ = try r.readSignatureValue(),
        else => return wire.ReadError.InvalidSignature,
    }
}

test "serialize/parse round-trips a method call" {
    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(std.testing.allocator);

    var body: std.ArrayList(u8) = .empty;
    defer body.deinit(std.testing.allocator);
    var bw = wire.Writer.init(std.testing.allocator, &body);
    try bw.writeString("hello-arg");

    try serialize(std.testing.allocator, &buf, .{
        .msg_type = .method_call,
        .serial = 1,
        .path = "/org/freedesktop/DBus",
        .interface = "org.freedesktop.DBus",
        .member = "Hello",
        .destination = "org.freedesktop.DBus",
        .signature = "s",
    }, body.items);

    const parsed = try parse(buf.items);
    try std.testing.expectEqual(MessageType.method_call, parsed.header.msg_type);
    try std.testing.expectEqual(@as(u32, 1), parsed.header.serial);
    try std.testing.expectEqualStrings("/org/freedesktop/DBus", parsed.header.path.?);
    try std.testing.expectEqualStrings("Hello", parsed.header.member.?);
    try std.testing.expectEqualStrings("s", parsed.header.signature.?);
    try std.testing.expectEqual(buf.items.len, parsed.consumed);

    var br = wire.Reader.init(parsed.body);
    try std.testing.expectEqualStrings("hello-arg", try br.readString());
}

test "totalLength matches serialize output size" {
    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(std.testing.allocator);
    try serialize(std.testing.allocator, &buf, .{
        .msg_type = .method_call,
        .serial = 7,
        .path = "/x",
        .interface = "i",
        .member = "m",
        .destination = "d",
    }, &[_]u8{});
    var prefix: [min_header_bytes]u8 = undefined;
    @memcpy(&prefix, buf.items[0..min_header_bytes]);
    try std.testing.expectEqual(buf.items.len, try totalLength(prefix));
}

test "parse accepts a big-endian message" {
    // Hand-crafted minimal method_return with REPLY_SERIAL=1, no body.
    // Endian 'B', type=2 (method_return), flags=0, version=1.
    // body_len=0, serial=42. header array length=8 (one (yv) entry).
    // (yv) entry: byte code=5 (REPLY_SERIAL), variant sig "u" then u32=1.
    const bytes = [_]u8{
        'B', 2, 0, 1,
        0, 0, 0, 0,
        0, 0, 0, 42,
        0, 0, 0, 8,
        5, 1, 'u', 0, 0, 0, 0, 1,
    };
    const parsed = try parse(&bytes);
    try std.testing.expectEqual(MessageType.method_return, parsed.header.msg_type);
    try std.testing.expectEqual(@as(u32, 42), parsed.header.serial);
    try std.testing.expectEqual(@as(u32, 1), parsed.header.reply_serial.?);
    try std.testing.expectEqual(@as(usize, 0), parsed.body.len);
}
