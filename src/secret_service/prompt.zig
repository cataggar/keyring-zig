//! `org.freedesktop.Secret.Prompt` handling.
//!
//! Several Secret Service methods (`CreateItem`, `Item.Delete`,
//! `Service.Unlock`, ...) may return a prompt object path. The client is
//! expected to:
//!
//!   1. Subscribe to the prompt's `Completed` signal,
//!   2. Call `Prompt(window_id)` on it,
//!   3. Wait for the `Completed(b dismissed, v result)` signal.
//!
//! If `dismissed` is true the user cancelled and we surface `error.Locked`;
//! otherwise the prompt succeeded and the caller can proceed (the result
//! variant content is operation-specific and not consumed here).

const std = @import("std");
const builtin = @import("builtin");
const Allocator = std.mem.Allocator;
const dbus = @import("dbus");
const wire = dbus.wire;
const connection = dbus.connection;

comptime {
    if (builtin.os.tag != .linux) @compileError("secret_service.prompt requires Linux");
}

pub const Error = connection.Error || error{Locked};

/// Run the prompt at `prompt_path` to completion. Returns when the user
/// either accepts the prompt or dismisses it (in which case the call
/// returns `error.Locked`).
pub fn run(conn: *connection.Connection, prompt_path: []const u8) Error!void {
    var rule_buf: std.ArrayList(u8) = .empty;
    defer rule_buf.deinit(conn.gpa);
    try rule_buf.appendSlice(
        conn.gpa,
        "type='signal',sender='org.freedesktop.secrets',interface='org.freedesktop.Secret.Prompt',member='Completed',path='",
    );
    try rule_buf.appendSlice(conn.gpa, prompt_path);
    try rule_buf.append(conn.gpa, '\'');
    try connection.addMatch(conn, rule_buf.items);
    defer connection.removeMatch(conn, rule_buf.items) catch {};

    // Call Prompt(window_id="").
    var body: std.ArrayList(u8) = .empty;
    defer body.deinit(conn.gpa);
    var w = wire.Writer.init(conn.gpa, &body);
    try w.writeString("");

    var reply = try connection.call(conn, .{
        .destination = "org.freedesktop.secrets",
        .path = prompt_path,
        .interface = "org.freedesktop.Secret.Prompt",
        .member = "Prompt",
        .signature = "s",
        .body = body.items,
    });
    defer reply.deinit();
    if (reply.err) |_| return Error.MethodCallFailed;

    // Wait for Completed(b, v).
    var sig = try connection.waitForSignal(
        conn,
        prompt_path,
        "org.freedesktop.Secret.Prompt",
        "Completed",
    );
    defer sig.deinit();

    var r = wire.Reader.init(sig.body);
    const dismissed = r.readBool() catch return Error.InvalidBool;
    if (dismissed) return error.Locked;
}
