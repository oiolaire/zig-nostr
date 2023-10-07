const std = @import("std");
const libsecp256k1 = @import("libsecp256k1.zig");
const keys = @import("keys.zig");
const string = @import("string.zig");

pub const Event = struct {
    kind: u16,
    content: []const u8,
    tags: [][][]const u8 = undefined,
    created_at: i64 = undefined,
    pubkey: [32]u8 = undefined,
    id: [32]u8 = undefined,
    sig: [64]u8 = undefined,

    fn serializeTags(self: Event, w: *string.String) !void {
        try w.concat("[");
        for (self.tags, 0..) |tag, t| {
            if (t != 0) {
                try w.concat(",");
            }
            try w.concat("[");
            for (tag, 0..) |item, i| {
                if (i != 0) {
                    try w.concat(",");
                }
                try std.json.encodeJsonString(item, .{}, w.writer());
            }
            try w.concat("]");
        }
        try w.concat("]");
    }
};

pub fn finalizeEvent(evt: *Event, sk: keys.SecretKey, allocator: std.mem.Allocator) !void {
    // set created_at if not set
    evt.created_at = std.time.timestamp();

    // write public key
    sk.serializedPublicKey(&evt.pubkey);

    // serialize and hash the event to obtain the id
    var s = string.init(allocator);
    defer s.deinit();
    try s.allocate("[0,'',,,[],'']".len + 64 + evt.content.len);
    try s.concat("[0,");
    try std.json.encodeJsonString(&std.fmt.bytesToHex(evt.pubkey, std.fmt.Case.lower), .{}, s.writer());
    try s.concat(",");
    try std.fmt.formatInt(evt.created_at, 10, std.fmt.Case.lower, .{}, s.writer());
    try s.concat(",");
    try std.fmt.formatInt(evt.kind, 10, std.fmt.Case.lower, .{}, s.writer());
    try s.concat(",");
    try evt.serializeTags(&s);
    try s.concat(",");
    try std.json.encodeJsonString(evt.content, .{}, s.writer());
    try s.concat("]");
    std.debug.print("str: {s}\n", .{s.str()});
    std.crypto.hash.sha2.Sha256.hash(s.str(), &evt.id, .{});

    // fill in the signature
    try sk.sign(&evt.sig, evt.id);
}

pub fn serializeEvent(evt: *Event, s: *string.String) []const u8 {
    try s.allocate("'id''','pubkey''','sig''','content''','tags'[],'kind'~~~~~,'created_at'~~~~~~~~~~,".len + 128 + 64 + 64 + evt.content.len);
}
