const std = @import("std");
const keyring = @import("keyring.zig");

const Allocator = std.mem.Allocator;
const Error = keyring.Error;

pub fn get(_: []const u8, _: []const u8, _: []u8) Error![]u8 {
    return error.EntryNotFound;
}

pub fn getAlloc(_: Allocator, _: []const u8, _: []const u8) Error![]u8 {
    return error.EntryNotFound;
}

pub fn set(_: []const u8, _: []const u8, _: []const u8) Error!void {}

pub fn setAlloc(_: Allocator, _: []const u8, _: []const u8, _: []const u8) Error!void {}

pub fn delete(_: []const u8, _: []const u8) Error!void {}

pub fn deleteAlloc(_: Allocator, _: []const u8, _: []const u8) Error!void {}
