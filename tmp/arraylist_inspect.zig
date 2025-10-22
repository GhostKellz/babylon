const std = @import("std");

pub fn main() void {
    const info = @typeInfo(std.ArrayList(u8));
    const struct_info = switch (info) {
        .@"struct" => |s| s,
        else => @compileError("not struct"),
    };
    inline for (struct_info.fields) |field| {
        @compileLog(field.name, field.type);
    }
    inline for (struct_info.decls) |decl| {
        @compileLog("decl", decl.name);
    }
}
