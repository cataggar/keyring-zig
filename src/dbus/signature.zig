//! D-Bus signature parsing utilities.
//!
//! Only the codes the Secret Service backend needs are recognised:
//! `y b n q i u x t d s o g h a ( ) { } v`.

const std = @import("std");

pub const Error = error{ InvalidSignature, UnknownTypeCode };

/// Alignment in bytes for a value whose signature starts with `code`.
/// Per the D-Bus specification, every value type has a fixed alignment.
pub fn alignmentOfCode(code: u8) Error!u8 {
    return switch (code) {
        'y' => 1,
        'b', 'i', 'u', 'h' => 4,
        'n', 'q' => 2,
        'x', 't', 'd' => 8,
        's', 'o' => 4,
        'g' => 1,
        'a' => 4,
        '(', '{' => 8,
        'v' => 1,
        else => Error.UnknownTypeCode,
    };
}

/// Length in bytes of the first complete type in `sig`.
/// `a...` is one prefix byte plus the element type. `(...)` and `{...}`
/// match their bracketed bodies (which may contain further nested types).
pub fn singleCompleteTypeLen(sig: []const u8) Error!usize {
    if (sig.len == 0) return Error.InvalidSignature;
    return switch (sig[0]) {
        'y', 'b', 'n', 'q', 'i', 'u', 'x', 't', 'd', 's', 'o', 'g', 'h', 'v' => 1,
        'a' => 1 + try singleCompleteTypeLen(sig[1..]),
        '(' => bracketedLen(sig, '(', ')'),
        '{' => bracketedLen(sig, '{', '}'),
        else => Error.UnknownTypeCode,
    };
}

fn bracketedLen(sig: []const u8, open: u8, close: u8) Error!usize {
    var depth: usize = 0;
    for (sig, 0..) |c, i| {
        if (c == open) depth += 1;
        if (c == close) {
            depth -= 1;
            if (depth == 0) return i + 1;
        }
    }
    return Error.InvalidSignature;
}

/// Iterator over the top-level complete types in a signature.
pub const Iterator = struct {
    sig: []const u8,
    idx: usize = 0,

    pub fn next(self: *Iterator) Error!?[]const u8 {
        if (self.idx >= self.sig.len) return null;
        const len = try singleCompleteTypeLen(self.sig[self.idx..]);
        const item = self.sig[self.idx .. self.idx + len];
        self.idx += len;
        return item;
    }
};

test "alignmentOfCode covers the Secret Service subset" {
    try std.testing.expectEqual(@as(u8, 1), try alignmentOfCode('y'));
    try std.testing.expectEqual(@as(u8, 4), try alignmentOfCode('u'));
    try std.testing.expectEqual(@as(u8, 4), try alignmentOfCode('s'));
    try std.testing.expectEqual(@as(u8, 4), try alignmentOfCode('o'));
    try std.testing.expectEqual(@as(u8, 1), try alignmentOfCode('g'));
    try std.testing.expectEqual(@as(u8, 4), try alignmentOfCode('a'));
    try std.testing.expectEqual(@as(u8, 8), try alignmentOfCode('('));
    try std.testing.expectEqual(@as(u8, 8), try alignmentOfCode('{'));
    try std.testing.expectEqual(@as(u8, 1), try alignmentOfCode('v'));
    try std.testing.expectError(Error.UnknownTypeCode, alignmentOfCode('?'));
}

test "singleCompleteTypeLen handles arrays and nested structs" {
    try std.testing.expectEqual(@as(usize, 1), try singleCompleteTypeLen("s"));
    try std.testing.expectEqual(@as(usize, 2), try singleCompleteTypeLen("ay"));
    try std.testing.expectEqual(@as(usize, 5), try singleCompleteTypeLen("a{ss}"));
    try std.testing.expectEqual(@as(usize, 8), try singleCompleteTypeLen("(oayays)"));
    try std.testing.expectEqual(@as(usize, 9), try singleCompleteTypeLen("a{oa{ss}}"));
}

test "Iterator walks top-level types" {
    var it: Iterator = .{ .sig = "sa{ss}ub" };
    try std.testing.expectEqualStrings("s", (try it.next()).?);
    try std.testing.expectEqualStrings("a{ss}", (try it.next()).?);
    try std.testing.expectEqualStrings("u", (try it.next()).?);
    try std.testing.expectEqualStrings("b", (try it.next()).?);
    try std.testing.expectEqual(@as(?[]const u8, null), try it.next());
}
