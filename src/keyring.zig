const std = @import("std");
const builtin = @import("builtin");
const build_options = @import("build_options");

const Allocator = std.mem.Allocator;

pub const Error = error{ EntryNotFound, NoStorageAccess, Locked, PlatformFailure, Ambiguous, OutOfMemory, InputTooLong, BufferTooSmall, InvalidUtf8 };
pub const Backend = enum { secret_service, keychain, win_credential, file, null_backend };

const native_backend: Backend = switch (builtin.os.tag) {
    .linux => .secret_service,
    .macos => .keychain,
    .windows => .win_credential,
    else => @compileError("Unsupported OS"),
};

const os_keyring = switch (builtin.os.tag) {
    .macos => @import("keyring-macos.zig"),
    .linux => @import("keyring-linux.zig"),
    .windows => @import("keyring-windows.zig"),
    else => @compileError("Unsupported OS"),
};
const null_keyring = @import("keyring-null.zig");
const file_keyring = @import("keyring-file.zig");
const secret_service = @import("secret_service");

var default_backend: ?Backend = null;
var env_backend_checked = false;
var env_backend: ?Backend = null;

pub fn currentBackend() Backend {
    if (default_backend) |backend| return backend;
    if (!env_backend_checked) {
        env_backend = readEnvBackend();
        env_backend_checked = true;
    }
    if (env_backend) |backend| return backend;
    return native_backend;
}

pub fn availableBackends(out: []Backend) []Backend {
    var len: usize = 0;
    if (len < out.len) {
        out[len] = native_backend;
        len += 1;
    }
    if (file_keyring.enabled and len < out.len) {
        out[len] = .file;
        len += 1;
    }
    if (len < out.len) {
        out[len] = .null_backend;
        len += 1;
    }
    return out[0..len];
}

pub fn setDefaultBackend(backend: Backend) error{BackendUnavailable}!void {
    if (!isBackendAvailable(backend)) return error.BackendUnavailable;
    default_backend = backend;
}

pub fn getProperty(gpa: Allocator, name: []const u8) Allocator.Error!?[]u8 {
    const prefix = "KEYRING_PROPERTY_";
    var env_name = try gpa.alloc(u8, prefix.len + name.len);
    defer gpa.free(env_name);

    @memcpy(env_name[0..prefix.len], prefix);
    for (env_name[prefix.len..], name) |*out, c| {
        out.* = std.ascii.toUpper(c);
    }

    return getEnvVarOwned(gpa, env_name);
}

pub fn get(service: []const u8, key: []const u8, out_buf: []u8) Error![]u8 {
    return switch (currentBackend()) {
        native_backend => os_keyring.get(service, key, out_buf) catch |err| return normalizeError(err),
        .file => if (file_keyring.enabled) file_keyring.get(service, key, out_buf) else unreachable,
        .null_backend => null_keyring.get(service, key, out_buf),
        else => unreachable,
    };
}

pub fn getAlloc(gpa: Allocator, service: []const u8, key: []const u8) Error![]u8 {
    return switch (currentBackend()) {
        native_backend => os_keyring.getAlloc(gpa, service, key) catch |err| return normalizeError(err),
        .file => if (file_keyring.enabled) file_keyring.getAlloc(gpa, service, key) else unreachable,
        .null_backend => null_keyring.getAlloc(gpa, service, key),
        else => unreachable,
    };
}

pub fn set(service: []const u8, key: []const u8, value: []const u8) Error!void {
    return switch (currentBackend()) {
        native_backend => os_keyring.set(service, key, value) catch |err| return normalizeError(err),
        .file => if (file_keyring.enabled) file_keyring.set(service, key, value) else unreachable,
        .null_backend => null_keyring.set(service, key, value),
        else => unreachable,
    };
}

pub fn setAlloc(gpa: Allocator, service: []const u8, key: []const u8, value: []const u8) Error!void {
    return switch (currentBackend()) {
        native_backend => os_keyring.setAlloc(gpa, service, key, value) catch |err| return normalizeError(err),
        .file => if (file_keyring.enabled) file_keyring.setAlloc(gpa, service, key, value) else unreachable,
        .null_backend => null_keyring.setAlloc(gpa, service, key, value),
        else => unreachable,
    };
}

pub fn delete(service: []const u8, key: []const u8) Error!void {
    return switch (currentBackend()) {
        native_backend => os_keyring.delete(service, key) catch |err| return normalizeError(err),
        .file => if (file_keyring.enabled) file_keyring.delete(service, key) else unreachable,
        .null_backend => null_keyring.delete(service, key),
        else => unreachable,
    };
}

pub fn deleteAlloc(gpa: Allocator, service: []const u8, key: []const u8) Error!void {
    return switch (currentBackend()) {
        native_backend => os_keyring.deleteAlloc(gpa, service, key) catch |err| return normalizeError(err),
        .file => if (file_keyring.enabled) file_keyring.deleteAlloc(gpa, service, key) else unreachable,
        .null_backend => null_keyring.deleteAlloc(gpa, service, key),
        else => unreachable,
    };
}

fn normalizeError(err: anyerror) Error {
    return switch (err) {
        error.EntryNotFound => error.EntryNotFound,
        error.NoStorageAccess => error.NoStorageAccess,
        error.Locked => error.Locked,
        error.PlatformFailure => error.PlatformFailure,
        error.Ambiguous => error.Ambiguous,
        error.OutOfMemory => error.OutOfMemory,
        error.InputTooLong => error.InputTooLong,
        error.BufferTooSmall => error.BufferTooSmall,
        error.InvalidUtf8 => error.InvalidUtf8,
        error.ServiceTooLong, error.KeyTooLong, error.ValueTooLong => error.InputTooLong,
        error.KeyChainReadError,
        error.KeyChainWriteError,
        error.KeyChainDeleteError,
        error.KeyChainCreateError,
        error.KeyChainUpdateError,
        error.CfStringCreationFailed,
        error.CfDataCreationFailed,
        => error.PlatformFailure,
        else => error.PlatformFailure,
    };
}

fn isBackendAvailable(backend: Backend) bool {
    return switch (backend) {
        native_backend, .null_backend => true,
        .file => file_keyring.enabled,
        else => false,
    };
}

fn readEnvBackend() ?Backend {
    if (builtin.os.tag == .wasi) return null;

    const value = getEnvVarOwned(std.heap.page_allocator, "KEYRING_BACKEND") catch return null;
    const owned = value orelse return null;
    defer std.heap.page_allocator.free(owned);

    const backend = parseBackend(owned) orelse return null;
    if (!isBackendAvailable(backend)) return null;
    return backend;
}

fn parseBackend(value: []const u8) ?Backend {
    if (std.mem.eql(u8, value, "secret_service")) return .secret_service;
    if (std.mem.eql(u8, value, "keychain")) return .keychain;
    if (std.mem.eql(u8, value, "win_credential")) return .win_credential;
    if (std.mem.eql(u8, value, "file")) return .file;
    if (std.mem.eql(u8, value, "null") or std.mem.eql(u8, value, "null_backend")) return .null_backend;
    return null;
}

fn getEnvVarOwned(gpa: Allocator, name: []const u8) Allocator.Error!?[]u8 {
    if (builtin.os.tag == .wasi) return null;

    if (builtin.os.tag == .windows) {
        var map = std.process.Environ.createMap(.{ .block = .global }, gpa) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return null,
        };
        defer map.deinit();
        if (map.get(name)) |value| return try gpa.dupe(u8, value);
        return null;
    }

    var i: usize = 0;
    while (std.c.environ[i]) |entry| : (i += 1) {
        const item = std.mem.span(entry);
        if (item.len > name.len and item[name.len] == '=' and std.mem.eql(u8, item[0..name.len], name)) {
            return try gpa.dupe(u8, item[name.len + 1 ..]);
        }
    }
    return null;
}

var next_test_id: u64 = 0;

fn randomTestName(comptime prefix: []const u8) [prefix.len + 16]u8 {
    var buf: [prefix.len + 16]u8 = undefined;
    next_test_id += 1;
    const suffix = next_test_id;
    _ = std.fmt.bufPrint(&buf, "{s}{x:0>16}", .{ prefix, suffix }) catch unreachable;
    return buf;
}

fn requireSecretServiceForTest() bool {
    return switch (builtin.os.tag) {
        .linux => secret_service.client.serviceAvailable(std.testing.allocator),
        else => true,
    };
}

test "get missing entry fails" {
    if (!requireSecretServiceForTest()) return;

    const service = randomTestName("keyring-zig-missing-service-");
    const key = randomTestName("keyring-zig-missing-key-");

    var buf: [64]u8 = undefined;
    try std.testing.expectError(error.EntryNotFound, get(&service, &key, &buf));
}

test "set then get works" {
    if (!requireSecretServiceForTest()) return;

    const service = randomTestName("keyring-zig-create-service-");
    const key = randomTestName("keyring-zig-create-key-");
    const value = "first-value";

    try set(&service, &key, value);
    defer delete(&service, &key) catch {};

    const got = try getAlloc(std.testing.allocator, &service, &key);
    defer std.testing.allocator.free(got);

    try std.testing.expectEqualSlices(u8, value, got);
}

test "setAlloc then get works" {
    if (!requireSecretServiceForTest()) return;

    const service = randomTestName("keyring-zig-alloc-create-service-");
    const key = randomTestName("keyring-zig-alloc-create-key-");
    const value = "alloc-value";

    try setAlloc(std.testing.allocator, &service, &key, value);
    defer deleteAlloc(std.testing.allocator, &service, &key) catch {};

    const got = try getAlloc(std.testing.allocator, &service, &key);
    defer std.testing.allocator.free(got);

    try std.testing.expectEqualSlices(u8, value, got);
}

test "set then modify works" {
    if (!requireSecretServiceForTest()) return;

    const service = randomTestName("keyring-zig-update-service-");
    const key = randomTestName("keyring-zig-update-key-");
    const first = "first-value";
    const second = "second-value";

    try set(&service, &key, first);
    defer delete(&service, &key) catch {};

    try set(&service, &key, second);

    const got = try getAlloc(std.testing.allocator, &service, &key);
    defer std.testing.allocator.free(got);

    try std.testing.expectEqualSlices(u8, second, got);
}

test "available backends include native and null" {
    var buf: [4]Backend = undefined;
    const backends = availableBackends(&buf);

    const expected_len: usize = if (file_keyring.enabled) 3 else 2;
    try std.testing.expectEqual(expected_len, backends.len);
    try std.testing.expectEqual(native_backend, backends[0]);
    if (file_keyring.enabled) {
        try std.testing.expectEqual(Backend.file, backends[1]);
        try std.testing.expectEqual(Backend.null_backend, backends[2]);
    } else {
        try std.testing.expectEqual(Backend.null_backend, backends[1]);
    }
}

test "setDefaultBackend rejects unavailable backend" {
    const unavailable: Backend = if (!file_keyring.enabled) .file else switch (native_backend) {
        .secret_service => .keychain,
        .keychain => .secret_service,
        .win_credential => .secret_service,
        .file, .null_backend => unreachable,
    };

    try std.testing.expectError(error.BackendUnavailable, setDefaultBackend(unavailable));
}

test "null backend dispatches without storage" {
    const old_default = default_backend;
    defer default_backend = old_default;
    default_backend = .null_backend;

    var buf: [8]u8 = undefined;
    try std.testing.expectError(error.EntryNotFound, get("service", "key", &buf));
    try std.testing.expectError(error.EntryNotFound, getAlloc(std.testing.allocator, "service", "key"));
    try set("service", "key", "value");
    try setAlloc(std.testing.allocator, "service", "key", "value");
    try delete("service", "key");
    try deleteAlloc(std.testing.allocator, "service", "key");
}

test "getProperty returns null for missing property" {
    const value = try getProperty(std.testing.allocator, "keyring_zig_unit_missing_property_0123456789");
    try std.testing.expect(value == null);
}
