# keyring-zig

Small cross-platform keyring access for Zig.

`keyring-zig` provides a minimal API for storing, reading, updating, and deleting secrets in the operating system credential store.

## Status

- macOS: supported
- Windows: supported
- Linux: supported via libsecret

## API

```zig
pub const Error = error{ EntryNotFound, NoStorageAccess, Locked, PlatformFailure, Ambiguous, OutOfMemory, InputTooLong, BufferTooSmall, InvalidUtf8 };
pub const Backend = enum { secret_service, keychain, win_credential, null_backend };

pub fn get(service: []const u8, key: []const u8, out_buf: []u8) Error![]u8
pub fn getAlloc(gpa: std.mem.Allocator, service: []const u8, key: []const u8) Error![]u8
pub fn set(service: []const u8, key: []const u8, value: []const u8) Error!void
pub fn setAlloc(gpa: std.mem.Allocator, service: []const u8, key: []const u8, value: []const u8) Error!void
pub fn delete(service: []const u8, key: []const u8) Error!void
pub fn deleteAlloc(gpa: std.mem.Allocator, service: []const u8, key: []const u8) Error!void

pub fn currentBackend() Backend
pub fn availableBackends(out: []Backend) []Backend
pub fn setDefaultBackend(b: Backend) error{BackendUnavailable}!void
pub fn getProperty(gpa: std.mem.Allocator, name: []const u8) std.mem.Allocator.Error!?[]u8
```

## Linux Notes

The Linux backend uses `libsecret`.

The non-allocating Linux calls currently use fixed stack buffers for NUL-terminated C-string conversion, so they impose a few input size limits:

- `get`: `service <= 512` bytes, `key <= 2048` bytes
- `set`: `service <= 512` bytes, `key <= 2048` bytes, `value <= 16 * 1024` bytes
- `delete`: `service <= 512` bytes, `key <= 2048` bytes

`getAlloc`, `setAlloc`, and `deleteAlloc` do not impose those `service` and `key` limits.

## Windows Notes

The non-allocating Windows calls use fixed-size UTF-16 conversion buffers, so they currently impose these input size limits:

- `get`: `service <= 512` bytes, `key <= 2048` bytes
- `set`: `service <= 512` bytes, `key <= 2048` bytes
- `delete`: `service <= 512` bytes, `key <= 2048` bytes

`getAlloc`, `setAlloc`, and `deleteAlloc` do not impose those `service` and `key` limits.

## Example

```zig
const std = @import("std");
const keyring = @import("keyring_zig");

pub fn main() !void {
    try keyring.set("my-app", "api-token", "secret-value");

    const value = try keyring.getAlloc(std.heap.page_allocator, "my-app", "api-token");
    defer std.heap.page_allocator.free(value);

    std.debug.print("stored value: {s}\n", .{value});
}
```

## Development

Run the test suite with:

```sh
zig build test
```

Tests exercise the public API against the platform credential store.
