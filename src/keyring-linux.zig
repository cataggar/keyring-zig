//! Linux backend dispatcher: forwards to either the libsecret-based or the
//! native pure-Zig Secret Service implementation, chosen at build time via
//! `-Dlinux-backend=libsecret|native`.

const build_options = @import("build_options");

const impl = switch (build_options.linux_backend) {
    .libsecret => @import("keyring-linux-libsecret.zig"),
    .native => @import("keyring-linux-native.zig"),
};

pub const get = impl.get;
pub const getAlloc = impl.getAlloc;
pub const set = impl.set;
pub const setAlloc = impl.setAlloc;
pub const delete = impl.delete;
pub const deleteAlloc = impl.deleteAlloc;
