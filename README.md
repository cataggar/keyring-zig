# keyring-zig

Small cross-platform keyring access for Zig.

`keyring-zig` provides a minimal API for storing, reading, updating, and deleting secrets in the operating system credential store.

## Status

- macOS: supported
- Windows: supported
- Linux: supported via libsecret
- File backend: optional, opt-in via `-Dfile-backend=true`

## API

```zig
pub const Error = error{ EntryNotFound, NoStorageAccess, Locked, PlatformFailure, Ambiguous, OutOfMemory, InputTooLong, BufferTooSmall, InvalidUtf8 };
pub const Backend = enum { secret_service, keychain, win_credential, file, null_backend };

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

## File backend (optional)

A portable file-backed store is available as a build-time opt-in. It is
intended for headless environments (CI, SSH-only servers, containers)
where no Secret Service / Keychain is available.

Enable it with the `file-backend` build option, both for the dependency
and when building your project:

```sh
zig build -Dfile-backend=true
```

Activation:

- `setDefaultBackend(.file)` at runtime, or
- `KEYRING_BACKEND=file` environment variable.

Configuration:

| Variable                  | Purpose                                                           |
|---------------------------|-------------------------------------------------------------------|
| `KEYRING_FILE_PATH`       | Absolute path to the store file (overrides the platform default). |
| `KEYRING_FILE_PASSPHRASE` | Required. Used to derive the AES-256-GCM key via Argon2id.        |

If `KEYRING_FILE_PASSPHRASE` is unset, every call returns `error.NoStorageAccess`
so a higher-level CLI can prompt the user and re-invoke with the variable
set.

Default store path (when `KEYRING_FILE_PATH` is not set):

| OS      | Path                                                       |
|---------|------------------------------------------------------------|
| Linux   | `${XDG_DATA_HOME:-$HOME/.local/share}/keyring/store.bin`   |
| macOS   | `~/Library/Application Support/keyring/store.bin`          |
| Windows | `%LOCALAPPDATA%\keyring\store.bin`                         |

Format and crypto:

- AES-256-GCM with a fresh 96-bit nonce per record.
- Key derived from the passphrase via Argon2id (`t=3`, `m=64 MiB`, `p=1`),
  with KDF parameters stored in the file header so they can be tuned later.
- A small AEAD `vcheck` value in the header lets a wrong passphrase surface
  as `error.Locked` before any records are touched.
- Atomic writes: the store is fully rewritten to a sibling `*.tmp` file,
  `fsync`'d, and `rename`'d into place. A sibling `*.lock` file holds the
  cross-process advisory lock (`flock` on POSIX, `LockFileEx` on Windows).

The file format is **not** wire-compatible with Python's
[`keyrings.cryptfile`](https://github.com/frispete/keyrings.cryptfile).

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
