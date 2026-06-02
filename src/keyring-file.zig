//! Optional file backend.
//!
//! Provides a portable, headless-friendly keyring store backed by a single
//! AES-256-GCM-encrypted file whose key is derived from a user passphrase via
//! Argon2id. The default store location follows XDG conventions on Linux,
//! `%LOCALAPPDATA%` on Windows, and `Application Support` on macOS. The path
//! can be overridden with `KEYRING_FILE_PATH`. The passphrase is read from
//! `KEYRING_FILE_PASSPHRASE`; if unset, `error.NoStorageAccess` is returned so
//! a higher-level CLI can prompt the user and re-invoke with the variable set.
//!
//! Not wire-compatible with Python's `keyrings.cryptfile`.

const std = @import("std");
const builtin = @import("builtin");
const build_options = @import("build_options");

const Allocator = std.mem.Allocator;
const Io = std.Io;
const Dir = Io.Dir;
const File = Io.File;
const Aes256Gcm = std.crypto.aead.aes_gcm.Aes256Gcm;
const argon2 = std.crypto.pwhash.argon2;

const Error = error{ EntryNotFound, NoStorageAccess, Locked, PlatformFailure, Ambiguous, OutOfMemory, InputTooLong, BufferTooSmall, InvalidUtf8 };

pub const enabled = build_options.enable_file_backend;

const magic: *const [8]u8 = "KRZIG\x00\x00\x01";
const aad_v1 = "keyring-zig/v1";
const vcheck_aad = "keyring-zig/vcheck/1";
const salt_len: usize = 16;
const nonce_len: usize = Aes256Gcm.nonce_length; // 12
const tag_len: usize = Aes256Gcm.tag_length; // 16
const key_len: usize = Aes256Gcm.key_length; // 32

const default_t_cost: u32 = 3;
const default_m_cost_kib: u32 = 64 * 1024; // 64 MiB
const default_p_cost: u24 = 1;

const max_field_len: u32 = 1 << 20; // 1 MiB per field; per-record sanity bound.
const max_records: u32 = 1 << 20;
const max_file_size: u64 = 256 * 1024 * 1024;

const env_path = "KEYRING_FILE_PATH";
const env_passphrase = "KEYRING_FILE_PASSPHRASE";

const Header = struct {
    t_cost: u32,
    m_cost_kib: u32,
    p_cost: u24,
    salt: [salt_len]u8,
    vcheck_nonce: [nonce_len]u8,
    vcheck_tag: [tag_len]u8,
};

const Record = struct {
    service: []u8,
    username: []u8,
    nonce: [nonce_len]u8,
    ciphertext: []u8,
    tag: [tag_len]u8,
};

const Store = struct {
    arena: std.heap.ArenaAllocator,
    header: Header,
    key: [key_len]u8,
    records: std.ArrayList(Record),

    fn deinit(self: *Store) void {
        std.crypto.secureZero(u8, &self.key);
        self.records.deinit(self.arena.child_allocator);
        self.arena.deinit();
    }
};

var process_mu: std.Io.Mutex = .init;

fn ioInstance() Io {
    return std.Io.Threaded.global_single_threaded.io();
}

pub fn get(service: []const u8, key: []const u8, out_buf: []u8) Error![]u8 {
    if (!enabled) unreachable;
    if (service.len > max_field_len or key.len > max_field_len) return error.InputTooLong;
    process_mu.lockUncancelable(ioInstance());
    defer process_mu.unlock(ioInstance());

    var gpa: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa.deinit();
    return getInner(gpa.allocator(), service, key, out_buf);
}

pub fn getAlloc(gpa: Allocator, service: []const u8, key: []const u8) Error![]u8 {
    if (!enabled) unreachable;
    if (service.len > max_field_len or key.len > max_field_len) return error.InputTooLong;
    process_mu.lockUncancelable(ioInstance());
    defer process_mu.unlock(ioInstance());

    const path = try resolvePath(gpa);
    defer gpa.free(path);
    const passphrase = try readPassphrase(gpa);
    defer freePassphrase(gpa, passphrase);

    return getAllocWith(gpa, path, passphrase, service, key);
}

pub fn set(service: []const u8, key: []const u8, value: []const u8) Error!void {
    if (!enabled) unreachable;
    if (service.len > max_field_len or key.len > max_field_len or value.len > max_field_len) {
        return error.InputTooLong;
    }
    process_mu.lockUncancelable(ioInstance());
    defer process_mu.unlock(ioInstance());

    var gpa: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa.deinit();
    return setInner(gpa.allocator(), service, key, value);
}

pub fn setAlloc(gpa: Allocator, service: []const u8, key: []const u8, value: []const u8) Error!void {
    if (!enabled) unreachable;
    if (service.len > max_field_len or key.len > max_field_len or value.len > max_field_len) {
        return error.InputTooLong;
    }
    process_mu.lockUncancelable(ioInstance());
    defer process_mu.unlock(ioInstance());

    return setInner(gpa, service, key, value);
}

pub fn delete(service: []const u8, key: []const u8) Error!void {
    if (!enabled) unreachable;
    if (service.len > max_field_len or key.len > max_field_len) return error.InputTooLong;
    process_mu.lockUncancelable(ioInstance());
    defer process_mu.unlock(ioInstance());

    var gpa: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa.deinit();
    return deleteInner(gpa.allocator(), service, key);
}

pub fn deleteAlloc(gpa: Allocator, service: []const u8, key: []const u8) Error!void {
    if (!enabled) unreachable;
    if (service.len > max_field_len or key.len > max_field_len) return error.InputTooLong;
    process_mu.lockUncancelable(ioInstance());
    defer process_mu.unlock(ioInstance());

    return deleteInner(gpa, service, key);
}

fn getInner(gpa: Allocator, service: []const u8, key: []const u8, out_buf: []u8) Error![]u8 {
    const path = try resolvePath(gpa);
    defer gpa.free(path);
    const passphrase = try readPassphrase(gpa);
    defer freePassphrase(gpa, passphrase);
    return getWith(gpa, path, passphrase, service, key, out_buf);
}

fn setInner(gpa: Allocator, service: []const u8, key: []const u8, value: []const u8) Error!void {
    const path = try resolvePath(gpa);
    defer gpa.free(path);
    const passphrase = try readPassphrase(gpa);
    defer freePassphrase(gpa, passphrase);
    return setWith(gpa, path, passphrase, service, key, value);
}

fn deleteInner(gpa: Allocator, service: []const u8, key: []const u8) Error!void {
    const path = try resolvePath(gpa);
    defer gpa.free(path);
    const passphrase = try readPassphrase(gpa);
    defer freePassphrase(gpa, passphrase);
    return deleteWith(gpa, path, passphrase, service, key);
}

fn getWith(gpa: Allocator, path: []const u8, passphrase: []const u8, service: []const u8, key: []const u8, out_buf: []u8) Error![]u8 {
    const io = ioInstance();
    try ensureParentDir(io, path);
    var lock = try acquireLock(io, gpa, path, .read_only);
    defer lock.deinit(io);

    var store = try openOrInitStore(gpa, path, passphrase, .read_only);
    defer store.deinit();

    const rec = findRecord(&store, service, key) orelse return error.EntryNotFound;
    if (out_buf.len < rec.ciphertext.len) return error.BufferTooSmall;
    const slice = out_buf[0..rec.ciphertext.len];
    try decryptRecord(&store.key, rec, slice);
    return slice;
}

fn getAllocWith(gpa: Allocator, path: []const u8, passphrase: []const u8, service: []const u8, key: []const u8) Error![]u8 {
    const io = ioInstance();
    try ensureParentDir(io, path);
    var lock = try acquireLock(io, gpa, path, .read_only);
    defer lock.deinit(io);

    var store = try openOrInitStore(gpa, path, passphrase, .read_only);
    defer store.deinit();

    const rec = findRecord(&store, service, key) orelse return error.EntryNotFound;
    const out = gpa.alloc(u8, rec.ciphertext.len) catch return error.OutOfMemory;
    errdefer gpa.free(out);
    try decryptRecord(&store.key, rec, out);
    return out;
}

fn setWith(gpa: Allocator, path: []const u8, passphrase: []const u8, service: []const u8, key: []const u8, value: []const u8) Error!void {
    const io = ioInstance();
    try ensureParentDir(io, path);
    var lock = try acquireLock(io, gpa, path, .read_write);
    defer lock.deinit(io);

    var store = try openOrInitStore(gpa, path, passphrase, .read_write);
    defer store.deinit();

    try upsertRecord(&store, service, key, value);
    try writeStore(gpa, path, &store);
}

fn deleteWith(gpa: Allocator, path: []const u8, passphrase: []const u8, service: []const u8, key: []const u8) Error!void {
    const io = ioInstance();
    try ensureParentDir(io, path);
    var lock = try acquireLock(io, gpa, path, .read_write);
    defer lock.deinit(io);

    var store = try openOrInitStore(gpa, path, passphrase, .read_write);
    defer store.deinit();

    if (!removeRecord(&store, service, key)) return error.EntryNotFound;
    try writeStore(gpa, path, &store);
}

const AccessMode = enum { read_only, read_write };

fn findRecord(store: *const Store, service: []const u8, key: []const u8) ?*const Record {
    for (store.records.items) |*rec| {
        if (std.mem.eql(u8, rec.service, service) and std.mem.eql(u8, rec.username, key)) {
            return rec;
        }
    }
    return null;
}

fn removeRecord(store: *Store, service: []const u8, key: []const u8) bool {
    var i: usize = 0;
    while (i < store.records.items.len) : (i += 1) {
        const rec = store.records.items[i];
        if (std.mem.eql(u8, rec.service, service) and std.mem.eql(u8, rec.username, key)) {
            _ = store.records.orderedRemove(i);
            return true;
        }
    }
    return false;
}

fn upsertRecord(store: *Store, service: []const u8, key: []const u8, value: []const u8) Error!void {
    const arena = store.arena.allocator();

    var nonce: [nonce_len]u8 = undefined;
    secureRandom(&nonce);

    const ciphertext = try arena.alloc(u8, value.len);
    var tag: [tag_len]u8 = undefined;
    const aad = try buildAad(arena, service, key);
    defer arena.free(aad);
    Aes256Gcm.encrypt(ciphertext, &tag, value, aad, nonce, store.key);

    for (store.records.items) |*rec| {
        if (std.mem.eql(u8, rec.service, service) and std.mem.eql(u8, rec.username, key)) {
            rec.nonce = nonce;
            rec.ciphertext = ciphertext;
            rec.tag = tag;
            return;
        }
    }

    const service_copy = try arena.dupe(u8, service);
    const key_copy = try arena.dupe(u8, key);
    try store.records.append(store.arena.child_allocator, .{
        .service = service_copy,
        .username = key_copy,
        .nonce = nonce,
        .ciphertext = ciphertext,
        .tag = tag,
    });
}

fn buildAad(gpa: Allocator, service: []const u8, key: []const u8) Allocator.Error![]u8 {
    var buf = try gpa.alloc(u8, aad_v1.len + 1 + service.len + 1 + key.len);
    var i: usize = 0;
    @memcpy(buf[i .. i + aad_v1.len], aad_v1);
    i += aad_v1.len;
    buf[i] = 0;
    i += 1;
    @memcpy(buf[i .. i + service.len], service);
    i += service.len;
    buf[i] = 0;
    i += 1;
    @memcpy(buf[i .. i + key.len], key);
    return buf;
}

fn decryptRecord(key: *const [key_len]u8, rec: *const Record, out: []u8) Error!void {
    std.debug.assert(out.len == rec.ciphertext.len);
    var arena_buf: [4096]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&arena_buf);
    const aad = try buildAadFba(fba.allocator(), rec.service, rec.username);
    Aes256Gcm.decrypt(out, rec.ciphertext, rec.tag, aad, rec.nonce, key.*) catch {
        return error.PlatformFailure;
    };
}

fn buildAadFba(gpa: Allocator, service: []const u8, key: []const u8) Error![]u8 {
    return buildAad(gpa, service, key) catch return error.OutOfMemory;
}

fn secureRandom(buf: []u8) void {
    const io = ioInstance();
    io.randomSecure(buf) catch {
        io.random(buf);
    };
}

fn deriveKey(out: *[key_len]u8, header: Header, passphrase: []const u8, gpa: Allocator) Error!void {
    argon2.kdf(
        gpa,
        out,
        passphrase,
        &header.salt,
        .{ .t = header.t_cost, .m = header.m_cost_kib, .p = header.p_cost },
        .argon2id,
        ioInstance(),
    ) catch return error.PlatformFailure;
}

fn computeVcheck(key: *const [key_len]u8, nonce: *[nonce_len]u8, tag: *[tag_len]u8) void {
    secureRandom(nonce);
    var ct: [0]u8 = .{};
    Aes256Gcm.encrypt(&ct, tag, "", vcheck_aad, nonce.*, key.*);
}

fn verifyVcheck(key: *const [key_len]u8, header: Header) Error!void {
    var ct: [0]u8 = .{};
    Aes256Gcm.decrypt(&ct, "", header.vcheck_tag, vcheck_aad, header.vcheck_nonce, key.*) catch {
        return error.Locked;
    };
}

const LockFile = struct {
    file: File,

    fn deinit(self: *LockFile, io: Io) void {
        self.file.unlock(io);
        self.file.close(io);
        self.* = undefined;
    }
};

fn acquireLock(io: Io, gpa: Allocator, path: []const u8, mode: AccessMode) Error!LockFile {
    const lock_path = std.fmt.allocPrint(gpa, "{s}.lock", .{path}) catch return error.OutOfMemory;
    defer gpa.free(lock_path);
    const f = Dir.cwd().createFile(io, lock_path, .{
        .truncate = false,
        .lock = switch (mode) {
            .read_only => .shared,
            .read_write => .exclusive,
        },
    }) catch return error.PlatformFailure;
    return .{ .file = f };
}

fn openOrInitStore(gpa: Allocator, path: []const u8, passphrase: []const u8, mode: AccessMode) Error!Store {
    const io = ioInstance();
    if (mode == .read_write) try ensureParentDir(io, path);

    var store: Store = .{
        .arena = std.heap.ArenaAllocator.init(gpa),
        .header = undefined,
        .key = undefined,
        .records = .empty,
    };
    errdefer store.deinit();

    // Read the file (if any) without holding an OS lock on the main file so
    // a subsequent atomic rename works on Windows. Cross-process safety is
    // provided by the sibling `<path>.lock` file held by the caller.
    var file = Dir.cwd().openFile(io, path, .{ .mode = .read_only }) catch |err| switch (err) {
        error.FileNotFound => {
            try initFreshStore(&store, passphrase, gpa);
            return store;
        },
        else => return error.PlatformFailure,
    };
    defer file.close(io);

    const size = file.length(io) catch return error.PlatformFailure;
    if (size == 0) {
        try initFreshStore(&store, passphrase, gpa);
        return store;
    }
    if (size > max_file_size) return error.PlatformFailure;

    const arena = store.arena.allocator();
    const bytes = arena.alloc(u8, @intCast(size)) catch return error.OutOfMemory;
    const n = file.readPositionalAll(io, bytes, 0) catch return error.PlatformFailure;
    if (n != bytes.len) return error.PlatformFailure;

    var cursor: usize = 0;
    store.header = try parseHeader(bytes, &cursor);
    try deriveKey(&store.key, store.header, passphrase, gpa);
    try verifyVcheck(&store.key, store.header);
    try parseRecords(&store, bytes, &cursor);
    return store;
}

fn initFreshStore(store: *Store, passphrase: []const u8, gpa: Allocator) Error!void {
    if (builtin.is_test) {
        if (test_kdf_override) |override| {
            store.header = override;
            try deriveKey(&store.key, store.header, passphrase, gpa);
            computeVcheck(&store.key, &store.header.vcheck_nonce, &store.header.vcheck_tag);
            return;
        }
    }
    store.header = .{
        .t_cost = default_t_cost,
        .m_cost_kib = default_m_cost_kib,
        .p_cost = default_p_cost,
        .salt = undefined,
        .vcheck_nonce = undefined,
        .vcheck_tag = undefined,
    };
    secureRandom(&store.header.salt);
    try deriveKey(&store.key, store.header, passphrase, gpa);
    computeVcheck(&store.key, &store.header.vcheck_nonce, &store.header.vcheck_tag);
}

fn parseHeader(bytes: []const u8, cursor: *usize) Error!Header {
    if (bytes.len < magic.len + 4) return error.PlatformFailure;
    if (!std.mem.eql(u8, bytes[0..magic.len], magic)) return error.PlatformFailure;
    cursor.* = magic.len;

    const header_len = std.mem.readInt(u32, bytes[cursor.* ..][0..4], .little);
    cursor.* += 4;
    if (header_len > 4096 or cursor.* + header_len > bytes.len) return error.PlatformFailure;
    const header_bytes = bytes[cursor.* .. cursor.* + header_len];
    cursor.* += header_len;

    var t_cost: ?u32 = null;
    var m_cost_kib: ?u32 = null;
    var p_cost: ?u24 = null;
    var salt: ?[salt_len]u8 = null;
    var vcheck: ?[nonce_len + tag_len]u8 = null;

    var it = std.mem.splitScalar(u8, header_bytes, '\n');
    while (it.next()) |line| {
        if (line.len == 0) continue;
        const eq = std.mem.indexOfScalar(u8, line, '=') orelse return error.PlatformFailure;
        const k = line[0..eq];
        const v = line[eq + 1 ..];
        if (std.mem.eql(u8, k, "kdf")) {
            if (!std.mem.eql(u8, v, "argon2id")) return error.PlatformFailure;
        } else if (std.mem.eql(u8, k, "v")) {
            // version marker; ignore but require == "19"
            if (!std.mem.eql(u8, v, "19")) return error.PlatformFailure;
        } else if (std.mem.eql(u8, k, "t")) {
            t_cost = std.fmt.parseInt(u32, v, 10) catch return error.PlatformFailure;
        } else if (std.mem.eql(u8, k, "m")) {
            m_cost_kib = std.fmt.parseInt(u32, v, 10) catch return error.PlatformFailure;
        } else if (std.mem.eql(u8, k, "p")) {
            p_cost = std.fmt.parseInt(u24, v, 10) catch return error.PlatformFailure;
        } else if (std.mem.eql(u8, k, "salt")) {
            var decoded: [salt_len]u8 = undefined;
            const dec = std.base64.standard.Decoder;
            const expected = dec.calcSizeForSlice(v) catch return error.PlatformFailure;
            if (expected != salt_len) return error.PlatformFailure;
            dec.decode(&decoded, v) catch return error.PlatformFailure;
            salt = decoded;
        } else if (std.mem.eql(u8, k, "vcheck")) {
            var decoded: [nonce_len + tag_len]u8 = undefined;
            const dec = std.base64.standard.Decoder;
            const expected = dec.calcSizeForSlice(v) catch return error.PlatformFailure;
            if (expected != nonce_len + tag_len) return error.PlatformFailure;
            dec.decode(&decoded, v) catch return error.PlatformFailure;
            vcheck = decoded;
        }
    }

    var h: Header = .{
        .t_cost = t_cost orelse return error.PlatformFailure,
        .m_cost_kib = m_cost_kib orelse return error.PlatformFailure,
        .p_cost = p_cost orelse return error.PlatformFailure,
        .salt = salt orelse return error.PlatformFailure,
        .vcheck_nonce = undefined,
        .vcheck_tag = undefined,
    };
    const vc = vcheck orelse return error.PlatformFailure;
    @memcpy(&h.vcheck_nonce, vc[0..nonce_len]);
    @memcpy(&h.vcheck_tag, vc[nonce_len..]);
    return h;
}

fn parseRecords(store: *Store, bytes: []const u8, cursor: *usize) Error!void {
    if (cursor.* + 4 > bytes.len) return error.PlatformFailure;
    const count = std.mem.readInt(u32, bytes[cursor.* ..][0..4], .little);
    cursor.* += 4;
    if (count > max_records) return error.PlatformFailure;

    const arena = store.arena.allocator();
    try store.records.ensureTotalCapacity(store.arena.child_allocator, count);

    var i: u32 = 0;
    while (i < count) : (i += 1) {
        const service = try readSlice(arena, bytes, cursor);
        const username = try readSlice(arena, bytes, cursor);
        if (cursor.* + nonce_len > bytes.len) return error.PlatformFailure;
        var nonce: [nonce_len]u8 = undefined;
        @memcpy(&nonce, bytes[cursor.* .. cursor.* + nonce_len]);
        cursor.* += nonce_len;
        const ciphertext = try readSlice(arena, bytes, cursor);
        if (cursor.* + tag_len > bytes.len) return error.PlatformFailure;
        var tag: [tag_len]u8 = undefined;
        @memcpy(&tag, bytes[cursor.* .. cursor.* + tag_len]);
        cursor.* += tag_len;
        store.records.appendAssumeCapacity(.{
            .service = service,
            .username = username,
            .nonce = nonce,
            .ciphertext = ciphertext,
            .tag = tag,
        });
    }
    if (cursor.* != bytes.len) return error.PlatformFailure;
}

fn readSlice(gpa: Allocator, bytes: []const u8, cursor: *usize) Error![]u8 {
    if (cursor.* + 4 > bytes.len) return error.PlatformFailure;
    const len = std.mem.readInt(u32, bytes[cursor.* ..][0..4], .little);
    cursor.* += 4;
    if (len > max_field_len or cursor.* + len > bytes.len) return error.PlatformFailure;
    const out = gpa.alloc(u8, len) catch return error.OutOfMemory;
    @memcpy(out, bytes[cursor.* .. cursor.* + len]);
    cursor.* += len;
    return out;
}

fn writeStore(gpa: Allocator, path: []const u8, store: *const Store) Error!void {
    const io = ioInstance();
    var buf = std.ArrayList(u8).empty;
    defer buf.deinit(gpa);

    try serializeStore(gpa, &buf, store);

    const tmp = try tempPath(gpa, path);
    defer gpa.free(tmp);

    {
        const f = Dir.cwd().createFile(io, tmp, .{
            .truncate = true,
            .lock = .none,
        }) catch return error.PlatformFailure;
        var closed = false;
        defer if (!closed) f.close(io);
        f.writePositionalAll(io, buf.items, 0) catch return error.PlatformFailure;
        f.sync(io) catch return error.PlatformFailure;
        f.close(io);
        closed = true;
    }

    Dir.cwd().rename(tmp, Dir.cwd(), path, io) catch return error.PlatformFailure;
}

fn serializeStore(gpa: Allocator, buf: *std.ArrayList(u8), store: *const Store) Error!void {
    try buf.appendSlice(gpa, magic);
    const header_text = try formatHeader(gpa, store.header);
    defer gpa.free(header_text);
    var len_buf: [4]u8 = undefined;
    std.mem.writeInt(u32, &len_buf, @intCast(header_text.len), .little);
    try buf.appendSlice(gpa, &len_buf);
    try buf.appendSlice(gpa, header_text);

    std.mem.writeInt(u32, &len_buf, @intCast(store.records.items.len), .little);
    try buf.appendSlice(gpa, &len_buf);

    for (store.records.items) |rec| {
        try writeSlice(gpa, buf, rec.service);
        try writeSlice(gpa, buf, rec.username);
        try buf.appendSlice(gpa, &rec.nonce);
        try writeSlice(gpa, buf, rec.ciphertext);
        try buf.appendSlice(gpa, &rec.tag);
    }
}

fn writeSlice(gpa: Allocator, buf: *std.ArrayList(u8), slice: []const u8) Error!void {
    var len_buf: [4]u8 = undefined;
    std.mem.writeInt(u32, &len_buf, @intCast(slice.len), .little);
    try buf.appendSlice(gpa, &len_buf);
    try buf.appendSlice(gpa, slice);
}

fn formatHeader(gpa: Allocator, h: Header) Error![]u8 {
    const enc = std.base64.standard.Encoder;
    var salt_b64_buf: [enc.calcSize(salt_len)]u8 = undefined;
    const salt_b64 = enc.encode(&salt_b64_buf, &h.salt);
    var vcheck_bytes: [nonce_len + tag_len]u8 = undefined;
    @memcpy(vcheck_bytes[0..nonce_len], &h.vcheck_nonce);
    @memcpy(vcheck_bytes[nonce_len..], &h.vcheck_tag);
    var vcheck_b64_buf: [enc.calcSize(nonce_len + tag_len)]u8 = undefined;
    const vcheck_b64 = enc.encode(&vcheck_b64_buf, &vcheck_bytes);

    return std.fmt.allocPrint(gpa,
        "kdf=argon2id\n" ++
            "v=19\n" ++
            "t={d}\n" ++
            "m={d}\n" ++
            "p={d}\n" ++
            "salt={s}\n" ++
            "vcheck={s}\n",
        .{ h.t_cost, h.m_cost_kib, h.p_cost, salt_b64, vcheck_b64 },
    ) catch return error.OutOfMemory;
}

fn tempPath(gpa: Allocator, path: []const u8) Error![]u8 {
    var suffix: [16]u8 = undefined;
    secureRandom(&suffix);
    const hex_buf = std.fmt.bytesToHex(suffix, .lower);
    return std.fmt.allocPrint(gpa, "{s}.tmp.{s}", .{ path, hex_buf }) catch return error.OutOfMemory;
}

fn ensureParentDir(io: Io, path: []const u8) Error!void {
    const parent = std.fs.path.dirname(path) orelse return;
    if (parent.len == 0) return;
    Dir.cwd().createDirPath(io, parent) catch |err| switch (err) {
        error.PathAlreadyExists => return,
        else => return error.PlatformFailure,
    };
}

fn resolvePath(gpa: Allocator) Error![]u8 {
    if (try getEnv(gpa, env_path)) |override| return override;

    return switch (builtin.os.tag) {
        .windows => try resolveWindowsPath(gpa),
        .macos => try resolveMacosPath(gpa),
        else => try resolveLinuxPath(gpa),
    };
}

fn resolveLinuxPath(gpa: Allocator) Error![]u8 {
    if (try getEnv(gpa, "XDG_DATA_HOME")) |xdg| {
        defer gpa.free(xdg);
        if (xdg.len != 0 and std.fs.path.isAbsolute(xdg)) {
            return std.fs.path.join(gpa, &.{ xdg, "keyring", "store.bin" }) catch return error.OutOfMemory;
        }
    }
    const home = (try getEnv(gpa, "HOME")) orelse return error.NoStorageAccess;
    defer gpa.free(home);
    return std.fs.path.join(gpa, &.{ home, ".local", "share", "keyring", "store.bin" }) catch return error.OutOfMemory;
}

fn resolveMacosPath(gpa: Allocator) Error![]u8 {
    const home = (try getEnv(gpa, "HOME")) orelse return error.NoStorageAccess;
    defer gpa.free(home);
    return std.fs.path.join(gpa, &.{ home, "Library", "Application Support", "keyring", "store.bin" }) catch return error.OutOfMemory;
}

fn resolveWindowsPath(gpa: Allocator) Error![]u8 {
    const local = (try getEnv(gpa, "LOCALAPPDATA")) orelse return error.NoStorageAccess;
    defer gpa.free(local);
    return std.fs.path.join(gpa, &.{ local, "keyring", "store.bin" }) catch return error.OutOfMemory;
}

fn readPassphrase(gpa: Allocator) Error![]u8 {
    if (try getEnv(gpa, env_passphrase)) |pw| {
        if (pw.len == 0) {
            freePassphrase(gpa, pw);
            return error.NoStorageAccess;
        }
        return pw;
    }
    // The CLI is expected to prompt and re-invoke with the env var set.
    return error.NoStorageAccess;
}

fn freePassphrase(gpa: Allocator, pw: []u8) void {
    std.crypto.secureZero(u8, pw);
    gpa.free(pw);
}

fn getEnv(gpa: Allocator, name: []const u8) Error!?[]u8 {
    if (builtin.os.tag == .wasi) return null;

    if (builtin.os.tag == .windows) {
        var map = std.process.Environ.createMap(.{ .block = .global }, gpa) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return null,
        };
        defer map.deinit();
        if (map.get(name)) |value| {
            if (value.len == 0) return null;
            return gpa.dupe(u8, value) catch error.OutOfMemory;
        }
        return null;
    }

    var i: usize = 0;
    while (std.c.environ[i]) |entry| : (i += 1) {
        const item = std.mem.span(entry);
        if (item.len > name.len and item[name.len] == '=' and std.mem.eql(u8, item[0..name.len], name)) {
            return gpa.dupe(u8, item[name.len + 1 ..]) catch error.OutOfMemory;
        }
    }
    return null;
}

test {
    if (!enabled) return;
    _ = magic;
}

const test_passphrase: []const u8 = "test-passphrase-keep-it-fast";

// Faster Argon2id params for tests; production callers get the defaults via
// `initFreshStore`. The override is a thread-local consumed by
// `initFreshStore` when `builtin.is_test` is true.
threadlocal var test_kdf_override: ?Header = null;

fn testStorePath(tmp_dir: *std.testing.TmpDir, name: []const u8, gpa: Allocator) ![]u8 {
    return std.fmt.allocPrint(gpa, ".zig-cache/tmp/{s}/{s}", .{
        @as([]const u8, &tmp_dir.sub_path),
        name,
    });
}

fn testInit() Header {
    var h: Header = .{
        .t_cost = 1,
        .m_cost_kib = 8,
        .p_cost = 1,
        .salt = undefined,
        .vcheck_nonce = undefined,
        .vcheck_tag = undefined,
    };
    secureRandom(&h.salt);
    return h;
}

test "file backend: set then get round-trips" {
    if (!enabled) return;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const gpa = std.testing.allocator;
    const path = try testStorePath(&tmp, "store.bin", gpa);
    defer gpa.free(path);

    try setWithFast(gpa, path, test_passphrase, "svc", "user", "secret-value");
    var buf: [64]u8 = undefined;
    const got = try getWith(gpa, path, test_passphrase, "svc", "user", &buf);
    try std.testing.expectEqualSlices(u8, "secret-value", got);
}

test "file backend: get missing entry returns EntryNotFound" {
    if (!enabled) return;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const gpa = std.testing.allocator;
    const path = try testStorePath(&tmp, "store.bin", gpa);
    defer gpa.free(path);

    try setWithFast(gpa, path, test_passphrase, "svc", "user", "v");
    var buf: [16]u8 = undefined;
    try std.testing.expectError(error.EntryNotFound, getWith(gpa, path, test_passphrase, "svc", "missing", &buf));
}

test "file backend: get on missing store returns EntryNotFound" {
    if (!enabled) return;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const gpa = std.testing.allocator;
    const path = try testStorePath(&tmp, "store.bin", gpa);
    defer gpa.free(path);

    var buf: [16]u8 = undefined;
    try std.testing.expectError(error.EntryNotFound, getWith(gpa, path, test_passphrase, "svc", "user", &buf));
}

test "file backend: set then modify updates record" {
    if (!enabled) return;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const gpa = std.testing.allocator;
    const path = try testStorePath(&tmp, "store.bin", gpa);
    defer gpa.free(path);

    try setWithFast(gpa, path, test_passphrase, "svc", "user", "first");
    try setWithFast(gpa, path, test_passphrase, "svc", "user", "second");
    const got = try getAllocWith(gpa, path, test_passphrase, "svc", "user");
    defer gpa.free(got);
    try std.testing.expectEqualSlices(u8, "second", got);
}

test "file backend: delete then get returns EntryNotFound" {
    if (!enabled) return;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const gpa = std.testing.allocator;
    const path = try testStorePath(&tmp, "store.bin", gpa);
    defer gpa.free(path);

    try setWithFast(gpa, path, test_passphrase, "svc", "user", "v");
    try deleteWith(gpa, path, test_passphrase, "svc", "user");
    var buf: [16]u8 = undefined;
    try std.testing.expectError(error.EntryNotFound, getWith(gpa, path, test_passphrase, "svc", "user", &buf));
}

test "file backend: delete missing returns EntryNotFound" {
    if (!enabled) return;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const gpa = std.testing.allocator;
    const path = try testStorePath(&tmp, "store.bin", gpa);
    defer gpa.free(path);

    try setWithFast(gpa, path, test_passphrase, "svc", "user", "v");
    try std.testing.expectError(error.EntryNotFound, deleteWith(gpa, path, test_passphrase, "svc", "missing"));
}

test "file backend: wrong passphrase returns Locked" {
    if (!enabled) return;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const gpa = std.testing.allocator;
    const path = try testStorePath(&tmp, "store.bin", gpa);
    defer gpa.free(path);

    try setWithFast(gpa, path, test_passphrase, "svc", "user", "v");
    var buf: [16]u8 = undefined;
    try std.testing.expectError(error.Locked, getWith(gpa, path, "different-passphrase", "svc", "user", &buf));
}

test "file backend: persists across reopen" {
    if (!enabled) return;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const gpa = std.testing.allocator;
    const path = try testStorePath(&tmp, "store.bin", gpa);
    defer gpa.free(path);

    try setWithFast(gpa, path, test_passphrase, "svc1", "user", "value1");
    try setWithFast(gpa, path, test_passphrase, "svc2", "user", "value2");

    const a = try getAllocWith(gpa, path, test_passphrase, "svc1", "user");
    defer gpa.free(a);
    try std.testing.expectEqualSlices(u8, "value1", a);

    const b = try getAllocWith(gpa, path, test_passphrase, "svc2", "user");
    defer gpa.free(b);
    try std.testing.expectEqualSlices(u8, "value2", b);
}

test "file backend: BufferTooSmall on undersized get buffer" {
    if (!enabled) return;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const gpa = std.testing.allocator;
    const path = try testStorePath(&tmp, "store.bin", gpa);
    defer gpa.free(path);

    try setWithFast(gpa, path, test_passphrase, "svc", "user", "0123456789");
    var buf: [4]u8 = undefined;
    try std.testing.expectError(error.BufferTooSmall, getWith(gpa, path, test_passphrase, "svc", "user", &buf));
}

test "file backend: getAlloc handles large values" {
    if (!enabled) return;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const gpa = std.testing.allocator;
    const path = try testStorePath(&tmp, "store.bin", gpa);
    defer gpa.free(path);

    const value = "x" ** 8192;
    try setWithFast(gpa, path, test_passphrase, "svc", "user", value);
    const got = try getAllocWith(gpa, path, test_passphrase, "svc", "user");
    defer gpa.free(got);
    try std.testing.expectEqualSlices(u8, value, got);
}

// Test-only fast variant of `setWith` that uses cheap Argon2id parameters
// so the suite stays interactive-fast. Production callers always pay the
// full default cost in `initFreshStore`.
fn setWithFast(gpa: Allocator, path: []const u8, passphrase: []const u8, service: []const u8, key: []const u8, value: []const u8) Error!void {
    test_kdf_override = testInit();
    defer test_kdf_override = null;
    return setWith(gpa, path, passphrase, service, key, value);
}
