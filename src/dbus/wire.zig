//! Alignment-aware writer and reader for D-Bus wire-format values.
//!
//! Both work in the buffer's own coordinate space, which matches D-Bus
//! semantics as long as the body is assembled starting at the message's
//! 8-byte-aligned body offset.

const std = @import("std");
const Allocator = std.mem.Allocator;
const types = @import("types.zig");

pub const WriteError = error{OutOfMemory};
pub const ReadError = error{ Truncated, InvalidString, InvalidBool, InvalidObjectPath, InvalidSignature };

pub const Writer = struct {
    buf: *std.ArrayList(u8),
    gpa: Allocator,
    endian: std.builtin.Endian = .little,

    pub fn init(gpa: Allocator, buf: *std.ArrayList(u8)) Writer {
        return .{ .buf = buf, .gpa = gpa };
    }

    pub fn len(self: *const Writer) usize {
        return self.buf.items.len;
    }

    pub fn alignTo(self: *Writer, n: usize) WriteError!void {
        const cur = self.buf.items.len;
        const target = std.mem.alignForward(usize, cur, n);
        var i = cur;
        while (i < target) : (i += 1) try self.buf.append(self.gpa, 0);
    }

    pub fn writeByte(self: *Writer, v: u8) WriteError!void {
        try self.buf.append(self.gpa, v);
    }

    pub fn writeBytes(self: *Writer, bytes: []const u8) WriteError!void {
        try self.buf.appendSlice(self.gpa, bytes);
    }

    pub fn writeU16(self: *Writer, v: u16) WriteError!void {
        try self.alignTo(2);
        var b: [2]u8 = undefined;
        std.mem.writeInt(u16, &b, v, self.endian);
        try self.buf.appendSlice(self.gpa, &b);
    }

    pub fn writeU32(self: *Writer, v: u32) WriteError!void {
        try self.alignTo(4);
        var b: [4]u8 = undefined;
        std.mem.writeInt(u32, &b, v, self.endian);
        try self.buf.appendSlice(self.gpa, &b);
    }

    pub fn writeU64(self: *Writer, v: u64) WriteError!void {
        try self.alignTo(8);
        var b: [8]u8 = undefined;
        std.mem.writeInt(u64, &b, v, self.endian);
        try self.buf.appendSlice(self.gpa, &b);
    }

    pub fn writeBool(self: *Writer, v: bool) WriteError!void {
        try self.writeU32(if (v) 1 else 0);
    }

    /// Marshal `s` or `o`: 4-byte length, UTF-8 bytes, trailing NUL.
    pub fn writeString(self: *Writer, s: []const u8) WriteError!void {
        try self.writeU32(@intCast(s.len));
        try self.buf.appendSlice(self.gpa, s);
        try self.buf.append(self.gpa, 0);
    }

    pub fn writeObjectPath(self: *Writer, s: []const u8) WriteError!void {
        try self.writeString(s);
    }

    /// Marshal `g`: 1-byte length, signature bytes, trailing NUL.
    pub fn writeSignatureValue(self: *Writer, s: []const u8) WriteError!void {
        try self.buf.append(self.gpa, @intCast(s.len));
        try self.buf.appendSlice(self.gpa, s);
        try self.buf.append(self.gpa, 0);
    }

    pub fn writeVariant(self: *Writer, v: types.Variant) WriteError!void {
        try self.writeSignatureValue(v.signature);
        if (v.signature.len > 0) {
            const elem_align = @import("signature.zig").alignmentOfCode(v.signature[0]) catch unreachable;
            try self.alignTo(elem_align);
        }
        try self.buf.appendSlice(self.gpa, v.body);
    }

    pub const ArrayHandle = struct { length_offset: usize, body_start: usize };

    /// Reserve a 4-byte length prefix and align to the element type. Caller writes
    /// elements and then closes with `endArray`. Empty arrays still consume the
    /// alignment padding for the element type.
    pub fn beginArray(self: *Writer, elem_align: usize) WriteError!ArrayHandle {
        try self.alignTo(4);
        const length_offset = self.buf.items.len;
        try self.buf.appendSlice(self.gpa, &[_]u8{ 0, 0, 0, 0 });
        try self.alignTo(elem_align);
        return .{ .length_offset = length_offset, .body_start = self.buf.items.len };
    }

    pub fn endArray(self: *Writer, h: ArrayHandle) void {
        const length: u32 = @intCast(self.buf.items.len - h.body_start);
        std.mem.writeInt(u32, self.buf.items[h.length_offset..][0..4], length, self.endian);
    }

    /// Align to the start of a struct or dict-entry (8-byte boundary).
    pub fn alignStruct(self: *Writer) WriteError!void {
        try self.alignTo(8);
    }
};

pub const Reader = struct {
    bytes: []const u8,
    pos: usize = 0,
    endian: std.builtin.Endian = .little,

    pub fn init(bytes: []const u8) Reader {
        return .{ .bytes = bytes };
    }

    pub fn remaining(self: *const Reader) usize {
        return self.bytes.len - self.pos;
    }

    pub fn alignTo(self: *Reader, n: usize) ReadError!void {
        const target = std.mem.alignForward(usize, self.pos, n);
        if (target > self.bytes.len) return ReadError.Truncated;
        // Padding bytes must be zero per spec, but be lenient on read.
        self.pos = target;
    }

    pub fn readByte(self: *Reader) ReadError!u8 {
        if (self.pos >= self.bytes.len) return ReadError.Truncated;
        const v = self.bytes[self.pos];
        self.pos += 1;
        return v;
    }

    pub fn readU16(self: *Reader) ReadError!u16 {
        try self.alignTo(2);
        if (self.pos + 2 > self.bytes.len) return ReadError.Truncated;
        const v = std.mem.readInt(u16, self.bytes[self.pos..][0..2], self.endian);
        self.pos += 2;
        return v;
    }

    pub fn readU32(self: *Reader) ReadError!u32 {
        try self.alignTo(4);
        if (self.pos + 4 > self.bytes.len) return ReadError.Truncated;
        const v = std.mem.readInt(u32, self.bytes[self.pos..][0..4], self.endian);
        self.pos += 4;
        return v;
    }

    pub fn readU64(self: *Reader) ReadError!u64 {
        try self.alignTo(8);
        if (self.pos + 8 > self.bytes.len) return ReadError.Truncated;
        const v = std.mem.readInt(u64, self.bytes[self.pos..][0..8], self.endian);
        self.pos += 8;
        return v;
    }

    pub fn readBool(self: *Reader) ReadError!bool {
        const v = try self.readU32();
        return switch (v) {
            0 => false,
            1 => true,
            else => ReadError.InvalidBool,
        };
    }

    pub fn readString(self: *Reader) ReadError![]const u8 {
        const length = try self.readU32();
        if (self.pos + length + 1 > self.bytes.len) return ReadError.Truncated;
        const s = self.bytes[self.pos .. self.pos + length];
        if (self.bytes[self.pos + length] != 0) return ReadError.InvalidString;
        self.pos += length + 1;
        return s;
    }

    pub fn readObjectPath(self: *Reader) ReadError![]const u8 {
        return self.readString();
    }

    pub fn readSignatureValue(self: *Reader) ReadError![]const u8 {
        const length = try self.readByte();
        if (self.pos + @as(usize, length) + 1 > self.bytes.len) return ReadError.Truncated;
        const s = self.bytes[self.pos .. self.pos + length];
        if (self.bytes[self.pos + length] != 0) return ReadError.InvalidSignature;
        self.pos += @as(usize, length) + 1;
        return s;
    }

    pub const ArrayBounds = struct { end: usize };

    pub fn beginArray(self: *Reader, elem_align: usize) ReadError!ArrayBounds {
        const length = try self.readU32();
        try self.alignTo(elem_align);
        if (self.pos + length > self.bytes.len) return ReadError.Truncated;
        return .{ .end = self.pos + length };
    }

    pub fn arrayHasMore(self: *const Reader, bounds: ArrayBounds) bool {
        return self.pos < bounds.end;
    }

    /// Read a raw byte slice of `len` bytes (no alignment).
    pub fn readBytes(self: *Reader, length: usize) ReadError![]const u8 {
        if (self.pos + length > self.bytes.len) return ReadError.Truncated;
        const s = self.bytes[self.pos .. self.pos + length];
        self.pos += length;
        return s;
    }

    pub fn alignStruct(self: *Reader) ReadError!void {
        try self.alignTo(8);
    }
};

test "writeString aligns and includes NUL" {
    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(std.testing.allocator);
    var w = Writer.init(std.testing.allocator, &buf);
    try w.writeString("foo");
    try std.testing.expectEqualSlices(u8, &[_]u8{ 3, 0, 0, 0, 'f', 'o', 'o', 0 }, buf.items);
}

test "writeU32 pads to 4-byte boundary" {
    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(std.testing.allocator);
    var w = Writer.init(std.testing.allocator, &buf);
    try w.writeByte(0xAA);
    try w.writeU32(0x11223344);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0xAA, 0, 0, 0, 0x44, 0x33, 0x22, 0x11 }, buf.items);
}

test "beginArray/endArray records body length" {
    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(std.testing.allocator);
    var w = Writer.init(std.testing.allocator, &buf);
    const h = try w.beginArray(4);
    try w.writeU32(1);
    try w.writeU32(2);
    try w.writeU32(3);
    w.endArray(h);
    try std.testing.expectEqualSlices(u8, &[_]u8{
        12, 0, 0, 0,
        1, 0, 0, 0,
        2, 0, 0, 0,
        3, 0, 0, 0,
    }, buf.items);
}

test "writeSignatureValue uses 1-byte length" {
    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(std.testing.allocator);
    var w = Writer.init(std.testing.allocator, &buf);
    try w.writeSignatureValue("a{sv}");
    try std.testing.expectEqualSlices(u8, &[_]u8{ 5, 'a', '{', 's', 'v', '}', 0 }, buf.items);
}

test "Reader round-trips writer output" {
    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(std.testing.allocator);
    var w = Writer.init(std.testing.allocator, &buf);
    try w.writeByte(0xAB);
    try w.writeU32(42);
    try w.writeString("hello");
    try w.writeObjectPath("/foo/bar");
    try w.writeSignatureValue("ao");

    var r = Reader.init(buf.items);
    try std.testing.expectEqual(@as(u8, 0xAB), try r.readByte());
    try std.testing.expectEqual(@as(u32, 42), try r.readU32());
    try std.testing.expectEqualStrings("hello", try r.readString());
    try std.testing.expectEqualStrings("/foo/bar", try r.readObjectPath());
    try std.testing.expectEqualStrings("ao", try r.readSignatureValue());
    try std.testing.expectEqual(@as(usize, 0), r.remaining());
}

test "Reader handles big-endian payloads" {
    const bytes = [_]u8{ 0x11, 0x22, 0x33, 0x44, 5, 0, 0, 0, 'h', 'e', 'l', 'l', 'o', 0 };
    var r = Reader.init(&bytes);
    r.endian = .big;
    try std.testing.expectEqual(@as(u32, 0x11223344), try r.readU32());
    r.endian = .little;
    try std.testing.expectEqualStrings("hello", try r.readString());
}
