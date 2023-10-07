const std = @import("std");
const ws = @import("ws");

pub fn connect(relay_url: []const u8, allocator: std.mem.Allocator) !void {
    var cli = try ws.connect(allocator, try std.Uri.parse(relay_url), &.{});
    defer cli.deinit(allocator);
}
