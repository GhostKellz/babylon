const std = @import("std");

pub fn main() void {
    const Managed = std.array_list.AlignedManaged(u8, null);
    const managed_info = @typeInfo(Managed);
    const managed_struct = switch (managed_info) {
        .@"struct" => |s| s,
        else => @compileError("Managed not struct"),
    };
    inline for (managed_struct.fields) |field| {
        @compileLog("managed_field", field.name, field.type);
    }

    const fetch_options_info = @typeInfo(std.http.Client.FetchOptions);
    const fetch_options_struct = switch (fetch_options_info) {
        .@"struct" => |s| s,
        else => @compileError("FetchOptions not struct"),
    };
    inline for (fetch_options_struct.fields) |field| {
        @compileLog("fetch_option_field", field.name, field.type);
    }

    const location_info = @typeInfo(std.http.Client.FetchOptions.Location);
    switch (location_info) {
        .@"union" => |u| {
            inline for (u.fields) |field| {
                @compileLog("location_tag", field.name, field.type);
            }
        },
        else => @compileLog("location_kind", location_info),
    }

    const fetch_result_info = @typeInfo(std.http.Client.FetchResult);
    const fetch_result_struct = switch (fetch_result_info) {
        .@"struct" => |s| s,
        else => @compileError("FetchResult not struct"),
    };
    inline for (fetch_result_struct.fields) |field| {
        @compileLog("fetch_result_field", field.name, field.type);
    }

    const request_info = @typeInfo(std.http.Client.Request);
    const request_struct = switch (request_info) {
        .@"struct" => |s| s,
        else => @compileError("Request not struct"),
    };
    inline for (request_struct.decls) |decl| {
        @compileLog("request_decl", decl.name);
    }
    @compileLog("receive_head_type", @TypeOf(std.http.Client.Request.receiveHead));
    @compileLog("send_bodyless_type", @TypeOf(std.http.Client.Request.sendBodiless));

    const response_info = @typeInfo(std.http.Client.Response);
    const response_struct = switch (response_info) {
        .@"struct" => |s| s,
        else => @compileError("Response not struct"),
    };
    inline for (response_struct.fields) |field| {
        @compileLog("response_field", field.name, field.type);
    }
    inline for (response_struct.decls) |decl| {
        @compileLog("response_decl", decl.name);
    }
    const response_head_info = @typeInfo(std.http.Client.Response.Head);
    const response_head_struct = switch (response_head_info) {
        .@"struct" => |s| s,
        else => @compileError("Response.Head not struct"),
    };
    inline for (response_head_struct.fields) |field| {
        @compileLog("response_head_field", field.name, field.type);
    }
    @compileLog("response_reader_type", @TypeOf(std.http.Client.Response.reader));
    @compileLog("response_body_err_type", @TypeOf(std.http.Client.Response.bodyErr));

    const client_info = @typeInfo(std.http.Client);
    const client_struct = switch (client_info) {
        .@"struct" => |s| s,
        else => @compileError("Client not struct"),
    };
    inline for (client_struct.decls) |decl| {
        @compileLog("client_decl", decl.name);
    }
    @compileLog("client_init_default_proxies_type", @TypeOf(std.http.Client.initDefaultProxies));

    inline for (client_struct.fields) |field| {
        @compileLog("client_field", field.name, field.type);
    }

    @compileLog("request_type", @TypeOf(std.http.Client.request));

    const redirect_info = @typeInfo(std.http.Client.Request.RedirectBehavior);
    switch (redirect_info) {
        .@"enum" => |e| {
            inline for (e.fields) |field| {
                @compileLog("redirect_behavior", field.name);
            }
        },
        else => @compileLog("redirect_behavior_kind", redirect_info),
    }

    const request_options_info = @typeInfo(std.http.Client.RequestOptions);
    const request_options_struct = switch (request_options_info) {
        .@"struct" => |s| s,
        else => @compileError("RequestOptions not struct"),
    };
    inline for (request_options_struct.fields) |field| {
        @compileLog("request_option_field", field.name, field.type);
    }

    const io_writer_info = @typeInfo(std.Io.Writer);
    const io_writer_struct = switch (io_writer_info) {
        .@"struct" => |s| s,
        else => @compileError("Io.Writer not struct"),
    };
    inline for (io_writer_struct.decls) |decl| {
        @compileLog("io_writer_decl", decl.name);
    }

    @compileLog("from_arraylist_type", @TypeOf(std.Io.Writer.fromArrayList));
    @compileLog("to_arraylist_type", @TypeOf(std.Io.Writer.toArrayList));

    const io_reader_info = @typeInfo(std.Io.Reader);
    const io_reader_struct = switch (io_reader_info) {
        .@"struct" => |s| s,
        else => @compileError("Io.Reader not struct"),
    };
    inline for (io_reader_struct.fields) |field| {
        @compileLog("io_reader_field", field.name, field.type);
    }
    inline for (io_reader_struct.decls) |decl| {
        @compileLog("io_reader_decl", decl.name);
    }
    @compileLog("reader_append_remaining_type", @TypeOf(std.Io.Reader.appendRemainingUnlimited));

    const reader_vtable_info = @typeInfo(std.Io.Reader.VTable);
    const reader_vtable_struct = switch (reader_vtable_info) {
        .@"struct" => |s| s,
        else => @compileError("Reader.VTable not struct"),
    };
    inline for (reader_vtable_struct.fields) |field| {
        @compileLog("io_reader_vtable_field", field.name, field.type);
    }

    const server_info = @typeInfo(std.http.Server);
    const server_struct = switch (server_info) {
        .@"struct" => |s| s,
        else => @compileError("Server not struct"),
    };
    inline for (server_struct.decls) |decl| {
        @compileLog("server_decl", decl.name);
    }
    @compileLog("server_init_type", @TypeOf(std.http.Server.init));
    @compileLog("server_receive_head_type", @TypeOf(std.http.Server.receiveHead));
}
