const std = @import("std");

pub fn main() void {
    const info = @typeInfo(std.http.Client);
    const struct_info = switch (info) {
        .@"struct" => |s| s,
        else => @compileError("Client not struct"),
    };
    inline for (struct_info.decls) |decl| {
        @compileLog(decl.name);
    }
    @compileLog(@TypeOf(std.http.Client.fetch));
    const fetch_info = @typeInfo(std.http.Client.FetchResult);
    const fetch_struct = switch (fetch_info) {
        .@"struct" => |s| s,
        else => @compileError("FetchResult not struct"),
    };
    @compileLog(fetch_struct.fields.len);
    inline for (fetch_struct.fields) |field| {
        @compileLog("fetch_field", field.name, field.type);
    }
    inline for (fetch_struct.decls) |decl| {
        @compileLog("fetch_decl", decl.name);
    }
}
