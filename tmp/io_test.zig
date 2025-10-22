const std = @import("std");

pub fn main() void {
    const reader_info = @typeInfo(std.Io.Reader);
    const reader_struct = switch (reader_info) {
        .@"struct" => |s| s,
        else => @compileError("Reader not struct"),
    };
    inline for (reader_struct.decls) |decl| {
        @compileLog(decl.name);
    }
    const writer_info = @typeInfo(std.Io.Writer);
    const writer_struct = switch (writer_info) {
        .@"struct" => |s| s,
        else => @compileError("Writer not struct"),
    };
    inline for (writer_struct.decls) |decl| {
        @compileLog(decl.name);
    }
}
