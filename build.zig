const std = @import("std");

const LinuxBackend = enum { libsecret, native };

fn linkPlatformDeps(module: *std.Build.Module, os_tag: std.Target.Os.Tag, linux_backend: LinuxBackend) void {
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
            switch (linux_backend) {
                .libsecret => {
                    module.linkSystemLibrary("libsecret-1", .{});
                    module.linkSystemLibrary("glib-2.0", .{});
                },
                .native => {
                    // No C library dependencies; the in-tree D-Bus client
                    // talks to org.freedesktop.secrets over AF_UNIX directly.
                },
            }
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

    const linux_backend = b.option(
        LinuxBackend,
        "linux-backend",
        "Linux Secret Service implementation: 'libsecret' (default; links libsecret-1 + glib-2.0) or 'native' (pure-Zig D-Bus client)",
    ) orelse .libsecret;

    const build_options = b.addOptions();
    build_options.addOption(bool, "enable_file_backend", enable_file_backend);
    build_options.addOption(LinuxBackend, "linux_backend", linux_backend);
    const build_options_mod = build_options.createModule();

    // Shared dbus + secret_service modules that the native Linux backend
    // imports. Built unconditionally so the modules are always testable.
    const dbus_mod = b.createModule(.{
        .root_source_file = b.path("src/dbus/dbus.zig"),
        .target = target,
    });
    if (target.result.os.tag == .linux) dbus_mod.link_libc = true;

    const ss_mod = b.createModule(.{
        .root_source_file = b.path("src/secret_service/secret_service.zig"),
        .target = target,
    });
    ss_mod.addImport("dbus", dbus_mod);
    if (target.result.os.tag == .linux) ss_mod.link_libc = true;

    const mod = b.addModule("keyring_zig", .{
        .root_source_file = b.path("src/keyring.zig"),
        .target = target,
    });
    mod.addImport("build_options", build_options_mod);
    mod.addImport("secret_service", ss_mod);
    linkPlatformDeps(mod, target.result.os.tag, linux_backend);

    const test_mod = b.createModule(.{
        .root_source_file = b.path("src/keyring.zig"),
        .target = target,
    });
    test_mod.addImport("build_options", build_options_mod);
    test_mod.addImport("secret_service", ss_mod);

    const mod_tests = b.addTest(.{
        .root_module = test_mod,
    });
    linkPlatformDeps(test_mod, target.result.os.tag, linux_backend);

    const run_mod_tests = b.addRunArtifact(mod_tests);
    const test_step = b.step("test", "Run tests");
    test_step.dependOn(&run_mod_tests.step);

    // Standalone tests for the in-tree D-Bus client. Built without any
    // platform-specific keyring deps so the dbus core can be exercised on
    // its own.
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

    // Standalone tests for the Secret Service client.
    const ss_test_mod = b.createModule(.{
        .root_source_file = b.path("src/secret_service/secret_service.zig"),
        .target = target,
    });
    ss_test_mod.addImport("dbus", dbus_mod);
    if (target.result.os.tag == .linux) ss_test_mod.link_libc = true;
    const ss_tests = b.addTest(.{
        .root_module = ss_test_mod,
    });
    const run_ss_tests = b.addRunArtifact(ss_tests);
    const ss_test_step = b.step("test-secret-service", "Run Secret Service client tests");
    ss_test_step.dependOn(&run_ss_tests.step);
    test_step.dependOn(&run_ss_tests.step);
}
