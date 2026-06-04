const std = @import("std");

pub const KeyringMacos = @This();

// Hand-rolled CoreFoundation / Security FFI declarations.
//
// We deliberately avoid `@cImport({ @cInclude("Security/Security.h"); ... })`
// because Zig's translate-c does not cope with newer macOS SDK headers:
//   * mach bitfield structs are emitted as `opaque {}`, then the SDK's
//     `_Static_assert(sizeof(...) == N)` fails to translate;
//   * `libDER` uses `__counted_by`, `__bidi_indexable`, etc.;
//   * the `__has_feature(x)=0` workaround papering over these breaks more
//     things on each new SDK release.
//
// Declaring only the symbols we actually use keeps the surface area tiny
// and SDK-version-independent. The frameworks themselves are linked via
// `linkPlatformDeps` in build.zig.

const __CFString = opaque {};
const __CFData = opaque {};
const __CFDictionary = opaque {};
const __CFAllocator = opaque {};
const __CFBoolean = opaque {};

const CFStringRef = ?*const __CFString;
const CFDataRef = ?*const __CFData;
const CFDictionaryRef = ?*const __CFDictionary;
const CFAllocatorRef = ?*const __CFAllocator;
const CFBooleanRef = ?*const __CFBoolean;
const CFTypeRef = ?*const anyopaque;
const CFIndex = c_long;
const Boolean = u8;
const CFStringEncoding = u32;
const UInt8 = u8;

const kCFStringEncodingUTF8: CFStringEncoding = 0x08000100;

const OSStatus = i32;
const errSecSuccess: OSStatus = 0;
const errSecItemNotFound: OSStatus = -25300;
const errSecAuthFailed: OSStatus = -25293;
const errSecInteractionNotAllowed: OSStatus = -25308;

// The CoreFoundation dictionary callback structs are opaque to us; we only
// ever pass a pointer to the framework-owned constants below.
const CFDictionaryKeyCallBacks = opaque {};
const CFDictionaryValueCallBacks = opaque {};

const kCFTypeDictionaryKeyCallBacks: *const CFDictionaryKeyCallBacks =
    @extern(*const CFDictionaryKeyCallBacks, .{ .name = "kCFTypeDictionaryKeyCallBacks" });
const kCFTypeDictionaryValueCallBacks: *const CFDictionaryValueCallBacks =
    @extern(*const CFDictionaryValueCallBacks, .{ .name = "kCFTypeDictionaryValueCallBacks" });

extern "c" const kCFBooleanTrue: CFBooleanRef;

extern "c" const kSecClass: CFStringRef;
extern "c" const kSecClassGenericPassword: CFStringRef;
extern "c" const kSecAttrService: CFStringRef;
extern "c" const kSecAttrAccount: CFStringRef;
extern "c" const kSecMatchLimit: CFStringRef;
extern "c" const kSecMatchLimitOne: CFStringRef;
extern "c" const kSecReturnData: CFStringRef;
extern "c" const kSecValueData: CFStringRef;

extern "c" fn CFStringCreateWithBytes(
    alloc: CFAllocatorRef,
    bytes: [*]const u8,
    numBytes: CFIndex,
    encoding: CFStringEncoding,
    isExternalRepresentation: Boolean,
) CFStringRef;

extern "c" fn CFDataCreate(
    allocator: CFAllocatorRef,
    bytes: [*]const u8,
    length: CFIndex,
) CFDataRef;

extern "c" fn CFDictionaryCreate(
    allocator: CFAllocatorRef,
    keys: [*]const CFTypeRef,
    values: [*]const CFTypeRef,
    numValues: CFIndex,
    keyCallBacks: ?*const CFDictionaryKeyCallBacks,
    valueCallBacks: ?*const CFDictionaryValueCallBacks,
) CFDictionaryRef;

extern "c" fn CFRelease(cf: CFTypeRef) void;
extern "c" fn CFDataGetLength(data: CFDataRef) CFIndex;
extern "c" fn CFDataGetBytePtr(data: CFDataRef) [*]const UInt8;

extern "c" fn SecItemCopyMatching(query: CFDictionaryRef, result: *CFTypeRef) OSStatus;
extern "c" fn SecItemAdd(attributes: CFDictionaryRef, result: ?*CFTypeRef) OSStatus;
extern "c" fn SecItemUpdate(query: CFDictionaryRef, attributesToUpdate: CFDictionaryRef) OSStatus;
extern "c" fn SecItemDelete(query: CFDictionaryRef) OSStatus;

fn makeCfString(bytes: []const u8) error{CfStringCreationFailed}!CFStringRef {
    const val = CFStringCreateWithBytes(null, bytes.ptr, @intCast(bytes.len), kCFStringEncodingUTF8, 0) orelse {
        return error.CfStringCreationFailed;
    };
    return val;
}

fn makeCfData(bytes: []const u8) error{CfDataCreationFailed}!CFDataRef {
    const val = CFDataCreate(null, bytes.ptr, @intCast(bytes.len)) orelse {
        return error.CfDataCreationFailed;
    };
    return val;
}

fn makeCfQueryDict(service: CFStringRef, key: CFStringRef, comptime minimal: bool) CFDictionaryRef {
    // Search query looks like
    //  kSecClass: type of password, e.g. kSecClassInternetPassword
    //  Attributes: attributes to search by. Availability depends on type, see https://developer.apple.com/documentation/security/item-class-keys-and-values#Item-class-values
    //  kSecMatchLimit: how many to fetch
    //  kSecReturnAttributes: bool wether to return attrs
    //  kSecReturnData: bool wether to return the data
    const len = comptime if (minimal) 3 else 5;
    var keys: [len]CFTypeRef = undefined;
    var values: [len]CFTypeRef = undefined;

    keys[0] = kSecClass;
    values[0] = kSecClassGenericPassword;

    keys[1] = kSecAttrService;
    values[1] = service;

    keys[2] = kSecAttrAccount;
    values[2] = key;

    if (!minimal) {
        keys[3] = kSecMatchLimit;
        values[3] = kSecMatchLimitOne;

        keys[4] = kSecReturnData;
        values[4] = kCFBooleanTrue;
    }

    const cf_attrs = CFDictionaryCreate(
        null,
        &keys,
        &values,
        len,
        kCFTypeDictionaryKeyCallBacks,
        kCFTypeDictionaryValueCallBacks,
    );
    return cf_attrs;
}

fn makeCfCreateDict(service: CFStringRef, key: CFStringRef, value: CFDataRef) CFDictionaryRef {
    var keys: [4]CFTypeRef = undefined;
    var values: [4]CFTypeRef = undefined;

    keys[0] = kSecClass;
    values[0] = kSecClassGenericPassword;

    keys[1] = kSecAttrService;
    values[1] = service;

    keys[2] = kSecAttrAccount;
    values[2] = key;

    keys[3] = kSecValueData;
    values[3] = value;

    const cf_dict = CFDictionaryCreate(
        null,
        &keys,
        &values,
        4,
        kCFTypeDictionaryKeyCallBacks,
        kCFTypeDictionaryValueCallBacks,
    );
    return cf_dict;
}

const KeyChainGetError = error{ EntryNotFound, Locked, KeyChainReadError, CfStringCreationFailed };
fn _getItem(service: []const u8, key: []const u8, out: *CFTypeRef) KeyChainGetError!OSStatus {
    const cf_service = try makeCfString(service);
    defer CFRelease(cf_service);

    const cf_key = try makeCfString(key);
    defer CFRelease(cf_key);

    const cf_attrs = makeCfQueryDict(cf_service, cf_key, false);
    defer CFRelease(cf_attrs);

    const status = SecItemCopyMatching(cf_attrs, out);
    if (status == errSecItemNotFound) return error.EntryNotFound;
    if (status == errSecInteractionNotAllowed or status == errSecAuthFailed) return error.Locked;
    if (status != errSecSuccess) return error.KeyChainReadError;
    return status;
}

const KeyChainBufferGetError = KeyChainGetError || error{BufferTooSmall};
pub fn get(service: []const u8, key: []const u8, out_buf: []u8) KeyChainBufferGetError![]u8 {
    var out: CFTypeRef = undefined;
    _ = try _getItem(service, key, &out);
    defer if (out) |value| CFRelease(value);

    const data: CFDataRef = @ptrCast(out.?);
    const len: usize = @intCast(CFDataGetLength(data));
    const ptr = CFDataGetBytePtr(data);
    if (out_buf.len < len) return error.BufferTooSmall;
    @memcpy(out_buf[0..len], ptr[0..len]);
    return out_buf[0..len];
}

const KeyChainAllocGetError = KeyChainGetError || error{OutOfMemory};
pub fn getAlloc(gpa: std.mem.Allocator, service: []const u8, key: []const u8) KeyChainAllocGetError![]u8 {
    var out: CFTypeRef = undefined;
    _ = try _getItem(service, key, &out);
    defer if (out) |value| CFRelease(value);

    const data: CFDataRef = @ptrCast(out.?);
    const len: usize = @intCast(CFDataGetLength(data));
    const ptr = CFDataGetBytePtr(data);
    const val = try gpa.dupe(u8, ptr[0..len]);
    return val;
}

const KeyChainUpdateError = error{ EntryNotFound, KeyChainUpdateError };
fn update(cf_service: CFStringRef, cf_key: CFStringRef, cf_value: CFDataRef) KeyChainUpdateError!void {
    const query = makeCfQueryDict(cf_service, cf_key, true);
    defer CFRelease(query);

    var keys: [1]CFTypeRef = undefined;
    var values: [1]CFTypeRef = undefined;

    keys[0] = kSecValueData;
    values[0] = cf_value;

    const attr_dict = CFDictionaryCreate(
        null,
        &keys,
        &values,
        1,
        kCFTypeDictionaryKeyCallBacks,
        kCFTypeDictionaryValueCallBacks,
    );
    defer CFRelease(attr_dict);

    const status = SecItemUpdate(query, attr_dict);
    if (status == errSecItemNotFound) return error.EntryNotFound;
    if (status != errSecSuccess) return error.KeyChainUpdateError;
}

const KeyChainWriteError = error{ KeyChainCreateError, KeyChainUpdateError, CfStringCreationFailed, CfDataCreationFailed };
pub fn set(service: []const u8, key: []const u8, value: []const u8) KeyChainWriteError!void {
    const cf_service = try makeCfString(service);
    defer CFRelease(cf_service);

    const cf_key = try makeCfString(key);
    defer CFRelease(cf_key);

    const cf_value = try makeCfData(value);
    defer CFRelease(cf_value);

    return update(cf_service, cf_key, cf_value) catch |err| switch (err) {
        error.EntryNotFound => {
            const attr_dict = makeCfCreateDict(cf_service, cf_key, cf_value);
            defer CFRelease(attr_dict);

            const status = SecItemAdd(attr_dict, null);
            if (status != errSecSuccess) return error.KeyChainCreateError;
        },
        error.KeyChainUpdateError => return error.KeyChainUpdateError,
    };
}

pub fn setAlloc(_: std.mem.Allocator, service: []const u8, key: []const u8, value: []const u8) KeyChainWriteError!void {
    return set(service, key, value);
}

const KeyChainDeleteError = error{ EntryNotFound, KeyChainDeleteError, CfStringCreationFailed };
pub fn delete(service: []const u8, key: []const u8) KeyChainDeleteError!void {
    const cf_service = try makeCfString(service);
    defer CFRelease(cf_service);

    const cf_key = try makeCfString(key);
    defer CFRelease(cf_key);

    const query = makeCfQueryDict(cf_service, cf_key, true);
    defer CFRelease(query);

    const status = SecItemDelete(query);
    if (status == errSecItemNotFound) return error.EntryNotFound;
    if (status != errSecSuccess) return error.KeyChainDeleteError;
}

pub fn deleteAlloc(_: std.mem.Allocator, service: []const u8, key: []const u8) KeyChainDeleteError!void {
    return delete(service, key);
}
