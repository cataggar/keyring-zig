const std = @import("std");

fn linkPlatformDeps(module: *std.Build.Module, os_tag: std.Target.Os.Tag) void {
    switch (os_tag) {
        .macos => {
            module.linkFramework("Security", .{});
            module.linkFramework("CoreFoundation", .{});
        },
        .windows => {
            module.linkSystemLibrary("Advapi32", .{});
        },
        .linux => {
            module.link_libc = true;
            module.linkSystemLibrary("libsecret-1", .{});
            module.linkSystemLibrary("glib-2.0", .{});
        },
        else => {},
    }
}

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});

    const enable_file_backend = b.option(
        bool,
        "file-backend",
        "Include the optional file backend (XDG path, AES-GCM, Argon2id passphrase)",
    ) orelse false;

    const build_options = b.addOptions();
    build_options.addOption(bool, "enable_file_backend", enable_file_backend);
    const build_options_mod = build_options.createModule();

    const mod = b.addModule("keyring_zig", .{
        .root_source_file = b.path("src/keyring.zig"),
        .target = target,
    });
    mod.addImport("build_options", build_options_mod);
    linkPlatformDeps(mod, target.result.os.tag);

    const test_mod = b.createModule(.{
        .root_source_file = b.path("src/keyring.zig"),
        .target = target,
    });
    test_mod.addImport("build_options", build_options_mod);

    const mod_tests = b.addTest(.{
        .root_module = test_mod,
    });
    linkPlatformDeps(test_mod, target.result.os.tag);

    const run_mod_tests = b.addRunArtifact(mod_tests);
    const test_step = b.step("test", "Run tests");
    test_step.dependOn(&run_mod_tests.step);

    // Standalone tests for the in-tree D-Bus client. Compiled without any
    // platform dependencies so they run on any host (and verify the dbus
    // core in isolation from the keyring backend).
    const dbus_test_mod = b.createModule(.{
        .root_source_file = b.path("src/dbus/dbus.zig"),
        .target = target,
    });
    if (target.result.os.tag == .linux) dbus_test_mod.link_libc = true;
    const dbus_tests = b.addTest(.{
        .root_module = dbus_test_mod,
    });
    const run_dbus_tests = b.addRunArtifact(dbus_tests);
    const dbus_test_step = b.step("test-dbus", "Run D-Bus core tests");
    dbus_test_step.dependOn(&run_dbus_tests.step);
    test_step.dependOn(&run_dbus_tests.step);
}
