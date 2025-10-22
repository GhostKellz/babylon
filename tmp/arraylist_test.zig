const std = @import("std");

pub fn main() void {}

test "arraylist instance init" {
    var list = std.ArrayList(u8){};
    list.init(std.testing.allocator);
    defer list.deinit();
    try list.append('a');
}
