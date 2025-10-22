const std = @import("std");
const ResponseBody = "Hello from Babylon prototype";

const AcceptContext = struct {
    server: *std.net.Server,
};

fn acceptOnce(ctx: AcceptContext) void {
    var connection = ctx.server.accept() catch |err| {
        std.debug.print("server accept error: {s}\n", .{@errorName(err)});
        return;
    };
    defer connection.stream.close();

    // Drain initial request bytes (ignore errors if client closes early).
    var temp_buffer: [512]u8 = undefined;
    _ = connection.stream.read(&temp_buffer) catch {};

    var response_buffer: [512]u8 = undefined;
    const response_bytes = std.fmt.bufPrint(
        &response_buffer,
        "HTTP/1.1 200 OK\r\n" ++
            "Content-Length: {d}\r\n" ++
            "Content-Type: text/plain\r\n" ++
            "Connection: close\r\n" ++
            "\r\n{s}",
        .{ ResponseBody.len, ResponseBody },
    ) catch |err| {
        std.debug.print("server format error: {s}\n", .{@errorName(err)});
        return;
    };

    connection.stream.writeAll(response_bytes) catch |err| {
        std.debug.print("server write error: {s}\n", .{@errorName(err)});
        return;
    };
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var listen_address = try std.net.Address.parseIp4("127.0.0.1", 0);
    var server = try listen_address.listen(.{ .reuse_address = true });
    defer server.deinit();

    const listen_addr = server.listen_address;
    const port = listen_addr.getPort();

    var accept_thread = try std.Thread.spawn(.{}, acceptOnce, .{AcceptContext{ .server = &server }});
    defer accept_thread.join();

    const url_text = try std.fmt.allocPrint(allocator, "http://127.0.0.1:{d}/", .{port});
    defer allocator.free(url_text);
    const uri = try std.Uri.parse(url_text);

    var client = std.http.Client{
        .allocator = allocator,
    };
    defer client.deinit();
    try client.initDefaultProxies(allocator);

    var request = try client.request(.GET, uri, .{});
    defer request.deinit();

    try request.sendBodiless();

    var header_buffer: [16 * 1024]u8 = undefined;
    var response = try request.receiveHead(&header_buffer);

    if (response.head.status != .ok) {
        std.debug.print("unexpected status: {s}\n", .{@tagName(response.head.status)});
        return error.UnexpectedStatus;
    }

    var reader_buffer: [4 * 1024]u8 = undefined;
    const reader = response.reader(&reader_buffer);

    var body = std.ArrayList(u8){
        .items = (@constCast(&[_]u8{}))[0..],
        .capacity = 0,
    };
    defer if (body.capacity != 0) allocator.free(body.items.ptr[0..body.capacity]);

    try reader.*.appendRemainingUnlimited(allocator, &body);

    if (response.bodyErr()) |body_error| {
        return body_error;
    }

    std.debug.print("Fetched {d} bytes: '{s}'\n", .{ body.items.len, body.items });

    try std.testing.expectEqualStrings(ResponseBody, body.items);
}
