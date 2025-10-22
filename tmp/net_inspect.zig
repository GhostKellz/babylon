const std = @import("std");

pub fn main() void {
    const info = @typeInfo(std.net.Address);
    const union_info = switch (info) {
        .@"union" => |u| u,
        else => @compileError("Address not union"),
    };
    inline for (union_info.decls) |decl| {
        @compileLog("address_decl", decl.name);
    }
    @compileLog("address_listen_type", @TypeOf(std.net.Address.listen));

    const server_info = @typeInfo(std.net.Server);
    const server_struct = switch (server_info) {
        .@"struct" => |s| s,
        else => @compileError("net.Server not struct"),
    };
    inline for (server_struct.decls) |decl| {
        @compileLog("net_server_decl", decl.name);
    }
    inline for (server_struct.fields) |field| {
        @compileLog("net_server_field", field.name, field.type);
    }

    const connection_info = @typeInfo(std.net.Server.Connection);
    const connection_struct = switch (connection_info) {
        .@"struct" => |s| s,
        else => @compileError("Server.Connection not struct"),
    };
    inline for (connection_struct.fields) |field| {
        @compileLog("net_connection_field", field.name, field.type);
    }
    inline for (connection_struct.decls) |decl| {
        @compileLog("net_connection_decl", decl.name);
    }

    const stream_info = @typeInfo(std.net.Stream);
    const stream_struct = switch (stream_info) {
        .@"struct" => |s| s,
        else => @compileError("net.Stream not struct"),
    };
    inline for (stream_struct.decls) |decl| {
        @compileLog("net_stream_decl", decl.name);
    }
    inline for (stream_struct.fields) |field| {
        @compileLog("net_stream_field", field.name, field.type);
    }

    const listen_options_info = @typeInfo(std.net.Address.ListenOptions);
    const listen_struct = switch (listen_options_info) {
        .@"struct" => |s| s,
        else => @compileError("ListenOptions not struct"),
    };
    inline for (listen_struct.fields) |field| {
        @compileLog("listen_option_field", field.name, field.type);
    }
}
