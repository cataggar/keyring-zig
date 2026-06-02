//! Linux Secret Service backend.
//!
//! Talks to `org.freedesktop.secrets` directly via the in-tree D-Bus client
//! (`src/dbus/`, `src/secret_service/`). No linkage against libsecret or glib.

const std = @import("std");
const ss = @import("secret_service");

const Allocator = std.mem.Allocator;
const Client = ss.client.Client;
const Error = ss.client.Error;

const service_max_len = 512;
const key_max_len = 2048;
const value_max_len = 16 * 1024;

pub const KeyChainGetError = error{ EntryNotFound, KeyChainReadError, BufferTooSmall, ServiceTooLong, KeyTooLong, OutOfMemory, Locked, NoStorageAccess };
pub const KeyChainAllocGetError = error{ EntryNotFound, KeyChainReadError, OutOfMemory, Locked, NoStorageAccess };
pub const KeyChainWriteError = error{ ServiceTooLong, KeyTooLong, ValueTooLong, KeyChainWriteError, OutOfMemory, Locked, NoStorageAccess };
pub const KeyChainAllocWriteError = error{ OutOfMemory, KeyChainWriteError, Locked, NoStorageAccess };
pub const KeyChainDeleteError = error{ ServiceTooLong, KeyTooLong, KeyChainDeleteError, EntryNotFound, OutOfMemory, Locked, NoStorageAccess };
pub const KeyChainAllocDeleteError = error{ OutOfMemory, KeyChainDeleteError, EntryNotFound, Locked, NoStorageAccess };

fn openClient(gpa: Allocator) Error!Client {
    return ss.client.open(gpa);
}

fn mapGetErr(err: Error) KeyChainGetError {
    return switch (err) {
        Error.EntryNotFound => error.EntryNotFound,
        Error.Locked => error.Locked,
        Error.NoStorageAccess => error.NoStorageAccess,
        Error.OutOfMemory => error.OutOfMemory,
        else => error.KeyChainReadError,
    };
}

fn mapGetAllocErr(err: Error) KeyChainAllocGetError {
    return switch (err) {
        Error.EntryNotFound => error.EntryNotFound,
        Error.Locked => error.Locked,
        Error.NoStorageAccess => error.NoStorageAccess,
        Error.OutOfMemory => error.OutOfMemory,
        else => error.KeyChainReadError,
    };
}

fn mapSetErr(err: Error) KeyChainWriteError {
    return switch (err) {
        Error.Locked => error.Locked,
        Error.NoStorageAccess => error.NoStorageAccess,
        Error.OutOfMemory => error.OutOfMemory,
        else => error.KeyChainWriteError,
    };
}

fn mapSetAllocErr(err: Error) KeyChainAllocWriteError {
    return switch (err) {
        Error.Locked => error.Locked,
        Error.NoStorageAccess => error.NoStorageAccess,
        Error.OutOfMemory => error.OutOfMemory,
        else => error.KeyChainWriteError,
    };
}

fn mapDeleteErr(err: Error) KeyChainDeleteError {
    return switch (err) {
        Error.EntryNotFound => error.EntryNotFound,
        Error.Locked => error.Locked,
        Error.NoStorageAccess => error.NoStorageAccess,
        Error.OutOfMemory => error.OutOfMemory,
        else => error.KeyChainDeleteError,
    };
}

fn mapDeleteAllocErr(err: Error) KeyChainAllocDeleteError {
    return switch (err) {
        Error.EntryNotFound => error.EntryNotFound,
        Error.Locked => error.Locked,
        Error.NoStorageAccess => error.NoStorageAccess,
        Error.OutOfMemory => error.OutOfMemory,
        else => error.KeyChainDeleteError,
    };
}

pub fn get(service: []const u8, key: []const u8, out_buf: []u8) KeyChainGetError![]u8 {
    if (service.len > service_max_len) return error.ServiceTooLong;
    if (key.len > key_max_len) return error.KeyTooLong;

    var gpa: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa.deinit();
    const a = gpa.allocator();

    var client = openClient(a) catch |e| return mapGetErr(e);
    defer client.deinit();

    const value = ss.client.get(&client, service, key, a) catch |e| return mapGetErr(e);
    defer a.free(value);

    if (out_buf.len < value.len) return error.BufferTooSmall;
    @memcpy(out_buf[0..value.len], value);
    return out_buf[0..value.len];
}

pub fn getAlloc(gpa: Allocator, service: []const u8, key: []const u8) KeyChainAllocGetError![]u8 {
    var client = openClient(gpa) catch |e| return mapGetAllocErr(e);
    defer client.deinit();
    return ss.client.get(&client, service, key, gpa) catch |e| mapGetAllocErr(e);
}

pub fn set(service: []const u8, key: []const u8, value: []const u8) KeyChainWriteError!void {
    if (service.len > service_max_len) return error.ServiceTooLong;
    if (key.len > key_max_len) return error.KeyTooLong;
    if (value.len > value_max_len) return error.ValueTooLong;

    var gpa: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa.deinit();
    const a = gpa.allocator();

    var client = openClient(a) catch |e| return mapSetErr(e);
    defer client.deinit();
    ss.client.set(&client, service, key, value) catch |e| return mapSetErr(e);
}

pub fn setAlloc(gpa: Allocator, service: []const u8, key: []const u8, value: []const u8) KeyChainAllocWriteError!void {
    var client = openClient(gpa) catch |e| return mapSetAllocErr(e);
    defer client.deinit();
    ss.client.set(&client, service, key, value) catch |e| return mapSetAllocErr(e);
}

pub fn delete(service: []const u8, key: []const u8) KeyChainDeleteError!void {
    if (service.len > service_max_len) return error.ServiceTooLong;
    if (key.len > key_max_len) return error.KeyTooLong;

    var gpa: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa.deinit();
    const a = gpa.allocator();

    var client = openClient(a) catch |e| return mapDeleteErr(e);
    defer client.deinit();
    ss.client.delete(&client, service, key) catch |e| return mapDeleteErr(e);
}

pub fn deleteAlloc(gpa: Allocator, service: []const u8, key: []const u8) KeyChainAllocDeleteError!void {
    var client = openClient(gpa) catch |e| return mapDeleteAllocErr(e);
    defer client.deinit();
    ss.client.delete(&client, service, key) catch |e| return mapDeleteAllocErr(e);
}
