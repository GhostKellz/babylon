const std = @import("std");

pub fn main() !void {
    comptime {
        @compileLog(std.meta.fields(@TypeOf(std.process.Child.run(.{ .allocator = std.testing.allocator, .argv = &[_][]const u8{"true"} }))));
    }
}
