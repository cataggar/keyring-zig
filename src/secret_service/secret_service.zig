//! Pure-Zig client for `org.freedesktop.Secret.Service`. Backs the Linux
//! `keyring_zig` API when built with `-Dlinux-backend=native`.

const std = @import("std");
const builtin = @import("builtin");

pub const encoding = @import("encoding.zig");
pub const session = if (builtin.os.tag == .linux) @import("session.zig") else struct {};
pub const prompt = if (builtin.os.tag == .linux) @import("prompt.zig") else struct {};
pub const client = if (builtin.os.tag == .linux) @import("client.zig") else struct {};

test {
    std.testing.refAllDecls(@This());
    _ = encoding;
    if (builtin.os.tag == .linux) {
        _ = session;
        _ = prompt;
        _ = client;
    }
}
