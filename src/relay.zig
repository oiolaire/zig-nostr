const std = @import("std");
const wz = @import("webzocket");
const filter = @import("filter.zig");
const envelope = @import("envelope.zig");

pub fn connect(allocator: std.mem.Allocator, relay_url: []const u8) !Relay {
    var client = wz.client.init(allocator);
    var conn = try client.connect(relay_url);

    return Relay{
        .url = relay_url,
        .client = client,
        .conn = conn,
        .allocator = allocator,
    };
}

pub const Relay = struct {
    url: []const u8,
    conn: wz.Conn,
    client: wz.client.Client,
    allocator: std.mem.Allocator,

    pub fn deinit(self: *Relay) void {
        self.conn.deinit();
        self.client.deinit();
        self.* = undefined;
    }

    pub fn req(self: Relay, flt: filter.Filter) ![]u8 {
        // TODO write directly to websocket instead of to a buffer then pass
        var str = try std.ArrayList(u8).initCapacity(self.allocator, 100);
        envelope.formatReq(flt, str);
        try self.conn.send(str.items);

        return self.conn.receive();
    }
};

test "connect to relay" {
    var relay = try connect("wss://nostr-pub.wellorder.net");
    defer relay.deinit();
}

test "read stuff" {
    var relay = try connect("wss://nostr-pub.wellorder.net");
    defer relay.deinit();

    var text = try relay.req(filter.Filter{ .limit = 1 });
    std.debug.print("got {s}\n", .{text});
}
