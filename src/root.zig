//! By convention, root.zig is the root source file when making a library.
const std = @import("std");

// Export core modules
pub const semver = @import("util/semver.zig");
pub const resolver = @import("resolver/resolver.zig");
pub const lockfile = @import("util/lockfile.zig");
pub const cache = @import("util/cache.zig");
pub const manifest = @import("util/manifest.zig");
pub const policy = @import("policy/policy.zig");
pub const registry = @import("registry/registry.zig");
pub const registry_git_index = @import("registry/git_index.zig");

pub fn bufferedPrint() !void {
    // Stdout is for the actual output of your application, for example if you
    // are implementing gzip, then only the compressed bytes should be sent to
    // stdout, not any debugging messages.
    var stdout_buffer: [1024]u8 = undefined;
    var stdout_writer = std.fs.File.stdout().writer(&stdout_buffer);
    const stdout = &stdout_writer.interface;

    try stdout.print("Run `zig build test` to run the tests.\n", .{});

    try stdout.flush(); // Don't forget to flush!
}

pub fn add(a: i32, b: i32) i32 {
    return a + b;
}

test "basic add functionality" {
    try std.testing.expect(add(3, 7) == 10);
}
