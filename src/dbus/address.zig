//! D-Bus bus address parsing.
//!
//! Only the unix transports required for the session bus are supported:
//! `unix:path=<path>`, `unix:abstract=<name>`, `unix:runtime=yes`.

const std = @import("std");

pub const Error = error{ UnsupportedTransport, InvalidAddress, MissingRuntimeDir, OutOfMemory };

pub const Address = union(enum) {
    path: []const u8,
    abstract: []const u8,
};

/// Parse a `;`-separated address string. Returns the first entry whose
/// transport we support. If an entry uses `runtime=yes`, `runtime_dir`
/// (typically `$XDG_RUNTIME_DIR`) is used to construct `<runtime_dir>/bus`;
/// pass `null` to skip runtime entries.
pub fn parse(gpa: std.mem.Allocator, input: []const u8, runtime_dir: ?[]const u8) Error!Address {
    var it = std.mem.splitScalar(u8, input, ';');
    while (it.next()) |raw| {
        const entry = std.mem.trim(u8, raw, " \t");
        if (entry.len == 0) continue;
        const colon = std.mem.indexOfScalar(u8, entry, ':') orelse continue;
        const transport = entry[0..colon];
        const params = entry[colon + 1 ..];
        if (!std.mem.eql(u8, transport, "unix")) continue;

        var path_value: ?[]const u8 = null;
        var abstract_value: ?[]const u8 = null;
        var use_runtime = false;

        var pit = std.mem.splitScalar(u8, params, ',');
        while (pit.next()) |kv| {
            const eq = std.mem.indexOfScalar(u8, kv, '=') orelse continue;
            const key = kv[0..eq];
            const value = kv[eq + 1 ..];
            if (std.mem.eql(u8, key, "path")) {
                path_value = value;
            } else if (std.mem.eql(u8, key, "abstract")) {
                abstract_value = value;
            } else if (std.mem.eql(u8, key, "runtime") and std.mem.eql(u8, value, "yes")) {
                use_runtime = true;
            }
        }

        if (path_value) |p| return .{ .path = try gpa.dupe(u8, p) };
        if (abstract_value) |a| return .{ .abstract = try gpa.dupe(u8, a) };
        if (use_runtime) {
            const dir = runtime_dir orelse return Error.MissingRuntimeDir;
            const joined = try std.fmt.allocPrint(gpa, "{s}/bus", .{dir});
            return .{ .path = joined };
        }
    }
    return Error.UnsupportedTransport;
}

pub fn free(gpa: std.mem.Allocator, addr: Address) void {
    switch (addr) {
        .path => |p| gpa.free(p),
        .abstract => |a| gpa.free(a),
    }
}

test "parse extracts unix path" {
    const a = try parse(std.testing.allocator, "unix:path=/run/user/1000/bus", null);
    defer free(std.testing.allocator, a);
    try std.testing.expectEqualStrings("/run/user/1000/bus", a.path);
}

test "parse extracts abstract name" {
    const a = try parse(std.testing.allocator, "unix:abstract=/tmp/dbus-XYZ,guid=abcd", null);
    defer free(std.testing.allocator, a);
    try std.testing.expectEqualStrings("/tmp/dbus-XYZ", a.abstract);
}

test "parse picks first supported entry" {
    const a = try parse(std.testing.allocator, "tcp:host=localhost;unix:path=/var/run/dbus/system_bus_socket", null);
    defer free(std.testing.allocator, a);
    try std.testing.expectEqualStrings("/var/run/dbus/system_bus_socket", a.path);
}

test "parse resolves runtime=yes against runtime_dir" {
    const a = try parse(std.testing.allocator, "unix:runtime=yes", "/run/user/1000");
    defer free(std.testing.allocator, a);
    try std.testing.expectEqualStrings("/run/user/1000/bus", a.path);
}

test "parse fails when no supported entry" {
    try std.testing.expectError(Error.UnsupportedTransport, parse(std.testing.allocator, "tcp:host=localhost,port=1234", null));
}

test "parse needs runtime_dir when only runtime=yes is offered" {
    try std.testing.expectError(Error.MissingRuntimeDir, parse(std.testing.allocator, "unix:runtime=yes", null));
}
