const std = @import("std");

pub fn main() !void {
    const allocator = std.heap.page_allocator;
    const source =
        \\.{
        \\    .name = .example,
        \\    .version = "0.0.1",
        \\    .dependencies = .{
        \\        .example = .{ .url = "https://example", .hash = "hash" },
        \\    },
        \\}
    ;

    const zontom = @import("zontom");
    var parser = zontom.Parser.init(allocator);
    defer parser.deinit();

    const document = try parser.parse(source);
    defer document.deinit(allocator);

    const table = document.root().asTable();
    _ = table;
}
