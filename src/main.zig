const std = @import("std");
const babylon = @import("babylon");
const cli = @import("cli/cli.zig");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    const exit_code = cli.run(allocator, args) catch |err| switch (err) {
        error.OutOfMemory => {
            std.debug.print("Error: Out of memory\n", .{});
            return err;
        },
        else => {
            std.debug.print("Error: {}\n", .{err});
            return err;
        },
    };

    std.process.exit(exit_code);
}
