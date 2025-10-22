const std = @import("std");

pub fn main() void {
    const info = @typeInfo(std.crypto.tls.Client);
    switch (info) {
        .@"struct" => |s| inline for (s.decls) |decl| {
            @compileLog(decl.name);
        },
        else => @compileLog("not struct"),
    }
}
