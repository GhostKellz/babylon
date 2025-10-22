const std = @import("std");
const zontom = @import("zontom");

pub fn main() void {}

comptime {
    @compileLog(@typeName(@TypeOf(zontom.Parser)));
}
