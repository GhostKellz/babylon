const std = @import("std");

pub fn main() !void {
    const allocator = std.heap.page_allocator;
    const cwd = std.fs.cwd();
    const data = try cwd.readFileAllocOptions(
        "build.zig.zon",
        allocator,
        std.Io.Limit.limited(1024 * 1024),
        std.mem.Alignment.of(u8),
        0,
    );
    defer allocator.free(data);

    var tree = try std.zig.Ast.parse(allocator, data, .zon);
    defer tree.deinit(allocator);

    const tokens = tree.tokens;
    const nodes_tag = tree.nodes.items(.tag);
    const nodes_main_token = tree.nodes.items(.main_token);

    std.debug.print("Mode: {s} tokens: {} nodes: {}\n", .{ @tagName(tree.mode), tokens.len, tree.nodes.len });
    for (nodes_tag, 0..) |tag, idx| {
        const main_token = nodes_main_token[idx];
        std.debug.print("node {d}: tag={s} main_token={d}\n", .{ idx, @tagName(tag), main_token });
        if (std.mem.eql(u8, @tagName(tag), "struct_init_dot_comma") or std.mem.eql(u8, @tagName(tag), "struct_init_dot_two_comma")) {
            var buf: [2]std.zig.Ast.Node.Index = undefined;
            if (tree.fullStructInit(&buf, @enumFromInt(idx))) |full| {
                std.debug.print("  fields: {d}\n", .{full.ast.fields.len});
                for (full.ast.fields, 0..) |field_node, f_idx| {
                    std.debug.print("    field[{d}] node={d} tag={s}\n", .{ f_idx, field_node, @tagName(tree.nodeTag(field_node)) });
                }
            }
        }
    }

    for (tokens.items(.tag), 0..) |tag, idx| {
        const start = tree.tokens.items(.start)[idx];
        const end = if (idx + 1 < tokens.len) tree.tokens.items(.start)[idx + 1] else data.len;
        std.debug.print("token {d}: tag={s} text='{s}'\n", .{ idx, @tagName(tag), data[start..end] });
    }
}
