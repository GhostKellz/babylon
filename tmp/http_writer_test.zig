const std = @import("std");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var contents = std.array_list.AlignedManaged(u8, null).init(allocator);
    defer contents.deinit();

    var writer = std.Io.Writer.fromArrayList(&contents.list);
    try writer.writeAll("hello");

    const slice = try contents.toOwnedSlice();
    defer allocator.free(slice);

    if (!std.mem.eql(u8, slice, "hello")) return error.Unexpected;
}
