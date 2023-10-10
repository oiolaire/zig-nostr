const std = @import("std");
const wz = @import("webzocket");

pub fn filter(relay_url: []const u8, allocator: std.mem.Allocator) !void {
    var client = wz.client.init(allocator);
    defer client.deinit();

    var conn = try client.connect(relay_url);
    defer conn.deinit();

    try conn.send("[\"REQ\", \"_\", {\"limit\": 1}]");
    var text = try conn.receive();

    std.debug.print("got {s}\n", .{text});
}

test "connect to relay" {
    try filter("wss://nostr-pub.wellorder.net", allocator);
}
