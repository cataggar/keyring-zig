//! Pure-Zig D-Bus client used by the Linux Secret Service backend.
//!
//! Only the subset needed by `keyring-linux.zig` is implemented:
//! synchronous method calls over an `AF_UNIX` session bus.

const std = @import("std");
const builtin = @import("builtin");

pub const types = @import("types.zig");
pub const signature = @import("signature.zig");
pub const wire = @import("wire.zig");
pub const message = @import("message.zig");
pub const address = @import("address.zig");
pub const auth = @import("auth.zig");
pub const connection = if (builtin.os.tag == .linux) @import("connection.zig") else struct {};

test {
    std.testing.refAllDecls(@This());
    _ = types;
    _ = signature;
    _ = wire;
    _ = message;
    _ = address;
    _ = auth;
    if (builtin.os.tag == .linux) _ = connection;
}
