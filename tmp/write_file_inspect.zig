const std = @import("std");

pub fn main() void {}

test "inspect Dir.writeFile" {
    const info = switch (@typeInfo(@TypeOf(std.fs.Dir.writeFile))) {
        .@"fn" => |f| f,
        else => @compileError("not a function"),
    };
    @compileLog(info.params.len);
    @compileLog(info.params[0].type);
    @compileLog(info.params[1].type);
    const opts_info = switch (@typeInfo(std.fs.Dir.WriteFileOptions)) {
        .@"struct" => |s| s,
        else => @compileError("WriteFileOptions not struct"),
    };
    inline for (opts_info.fields) |field| {
        @compileLog(field.name);
        @compileLog(field.type);
    }
}
