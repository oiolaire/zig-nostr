const std = @import("std");
const libsecp256k1 = @import("libsecp256k1.zig");
const keys = @import("keys.zig");
const string = @import("string.zig");

pub const ValidationError = error{ IdDoesntMatch, InvalidPublicKey, InvalidSignature, InternalError };
pub const DeserializationError = error{ UnexpectedToken, UnexpectedValue, TooManyTagItems };

const MAX_TAG_ITEMS = 32;

pub fn deserialize(json: []const u8, allocator: std.mem.Allocator) !Event {
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();

    var aa = arena.allocator();
    var scanner = std.json.Scanner.initCompleteInput(aa, json);
    defer scanner.deinit();

    if (.object_begin != try scanner.next()) return DeserializationError.UnexpectedToken;

    var event = Event{};
    var missing_fields: u8 = 7;
    while (missing_fields > 0) {
        var name_token: ?std.json.Token = try scanner.nextAllocMax(aa, .alloc_if_needed, std.json.default_max_value_len);
        switch (name_token.?) {
            inline .string, .allocated_string => |name| {
                if (std.mem.eql(u8, name, "id")) {
                    var val = try scanner.next();
                    if (val == .string) {
                        _ = try std.fmt.hexToBytes(
                            &event.id,
                            val.string,
                        );
                    } else {
                        return DeserializationError.UnexpectedValue;
                    }
                } else if (std.mem.eql(u8, name, "pubkey")) {
                    var val = try scanner.next();
                    if (val == .string) {
                        _ = try std.fmt.hexToBytes(
                            &event.pubkey,
                            val.string,
                        );
                    } else {
                        return DeserializationError.UnexpectedValue;
                    }
                } else if (std.mem.eql(u8, name, "kind")) {
                    var val = try scanner.next();
                    if (val == .number) {
                        event.kind = try std.fmt.parseInt(u16, val.number, 10);
                    } else {
                        return DeserializationError.UnexpectedValue;
                    }
                } else if (std.mem.eql(u8, name, "created_at")) {
                    var val = try scanner.next();
                    if (val == .number) {
                        event.created_at = try std.fmt.parseInt(i64, val.number, 10);
                    } else {
                        return DeserializationError.UnexpectedValue;
                    }
                } else if (std.mem.eql(u8, name, "content")) {
                    var val = try scanner.next();
                    if (val == .string) {
                        event.content = val.string;
                    } else {
                        return DeserializationError.UnexpectedValue;
                    }
                } else if (std.mem.eql(u8, name, "tags")) {
                    var tags = try std.ArrayList([][]const u8).initCapacity(allocator, 15);
                    if (.array_begin != try scanner.next()) return DeserializationError.UnexpectedToken;
                    var tag_open = false;

                    var tag: [][]const u8 = try allocator.alloc([]const u8, MAX_TAG_ITEMS);
                    defer allocator.free(tag);

                    var t: usize = 0;
                    while (true) {
                        switch (try scanner.next()) {
                            .array_begin => {
                                if (tag_open) {
                                    // can't have arrays inside tags
                                    return DeserializationError.UnexpectedValue;
                                }

                                // initializing a tag
                                tag_open = true;
                                t = 0;
                            },
                            .array_end => {
                                if (tag_open) {
                                    // closing a tag
                                    tag_open = false;
                                    try tags.append(tag);
                                } else {
                                    // closing the tags list
                                    break;
                                }
                            },
                            .string => |v| {
                                if (!tag_open) {
                                    // can't have a loose string inside the tags array
                                    return DeserializationError.UnexpectedValue;
                                }

                                // an item inside a tag
                                tag[t] = v;
                                t += 1;
                                if (t > MAX_TAG_ITEMS) {
                                    return DeserializationError.TooManyTagItems;
                                }
                            },
                            else => {
                                // this is not a valid tag
                                return DeserializationError.UnexpectedValue;
                            },
                        }
                    }

                    event.tags = try tags.toOwnedSlice();
                } else if (std.mem.eql(u8, name, "sig")) {
                    var val = try scanner.next();
                    if (val == .string) {
                        _ = try std.fmt.hexToBytes(
                            &event.sig,
                            val.string,
                        );
                    } else {
                        return DeserializationError.UnexpectedValue;
                    }
                } else {
                    continue;
                }
                missing_fields -= 1;
            },
            else => {
                std.debug.print("unexpected={?}\n", .{name_token});
            },
        }
    }

    return event;
}

pub const Event = struct {
    kind: u16 = 1,
    content: []const u8 = &.{},
    tags: [][][]const u8 = &.{},
    created_at: i64 = undefined,
    pubkey: [32]u8 = undefined,
    id: [32]u8 = undefined,
    sig: [64]u8 = undefined,

    pub fn verify(self: Event, allocator: std.mem.Allocator) ValidationError!void {
        // check id
        var s = string.init(allocator);
        defer s.deinit();

        self.serializeForHashing(&s) catch |err| switch (err) {
            error.OutOfMemory => return ValidationError.InternalError,
            error.InvalidRange => unreachable,
        };

        var id: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(s.str(), &id, .{});
        if (!std.mem.eql(u8, &id, &self.id)) {
            return ValidationError.IdDoesntMatch;
        }

        // check signature
        const ctx = libsecp256k1.getContext();
        var xonly_pk: libsecp256k1.secp256k1_xonly_pubkey = undefined;
        if (0 == libsecp256k1.secp256k1_xonly_pubkey_parse(ctx, &xonly_pk, &self.pubkey)) {
            return ValidationError.InvalidPublicKey;
        }

        if (0 == libsecp256k1.secp256k1_schnorrsig_verify(ctx, &self.sig, &id, 32, &xonly_pk)) {
            return ValidationError.InvalidSignature;
        }
    }

    pub fn finalize(self: *Event, sk: keys.SecretKey, allocator: std.mem.Allocator) !void {
        // set created_at if not set
        self.created_at = std.time.timestamp();

        // write public key
        sk.serializedPublicKey(&self.pubkey);

        // serialize and hash the event to obtain the id
        var s = string.init(allocator);
        defer s.deinit();
        try self.serializeForHashing(&s);
        std.crypto.hash.sha2.Sha256.hash(s.str(), &self.id, .{});

        // fill in the signature
        try sk.sign(&self.sig, self.id);
    }

    pub fn serialize(self: *Event, s: *string.String) !void {
        try s.allocate("'id''','pubkey''','sig''','content''','tags'[],'kind'~~~~~,'created_at'~~~~~~~~~~,".len + 128 + 64 + 64 + self.content.len);
        try s.concat("{\"id\":");
        try std.json.encodeJsonString(&std.fmt.bytesToHex(self.id, std.fmt.Case.lower), .{}, s.writer());
        try s.concat(",\"sig\":");
        try std.json.encodeJsonString(&std.fmt.bytesToHex(self.sig, std.fmt.Case.lower), .{}, s.writer());
        try s.concat(",\"pubkey\":");
        try std.json.encodeJsonString(&std.fmt.bytesToHex(self.pubkey, std.fmt.Case.lower), .{}, s.writer());
        try s.concat(",\"created_at\":");
        try std.fmt.formatInt(self.created_at, 10, std.fmt.Case.lower, .{}, s.writer());
        try s.concat(",\"kind\":");
        try std.fmt.formatInt(self.kind, 10, std.fmt.Case.lower, .{}, s.writer());
        try s.concat(",\"tags\":");
        try self.serializeTags(s);
        try s.concat(",\"content\":");
        try std.json.encodeJsonString(self.content, .{}, s.writer());
        try s.concat("}");
    }

    fn serializeForHashing(self: Event, s: *string.String) !void {
        try s.allocate("[0,'',,,[],'']".len + 64 + self.content.len);
        try s.concat("[0,");
        try std.json.encodeJsonString(&std.fmt.bytesToHex(self.pubkey, std.fmt.Case.lower), .{}, s.writer());
        try s.concat(",");
        try std.fmt.formatInt(self.created_at, 10, std.fmt.Case.lower, .{}, s.writer());
        try s.concat(",");
        try std.fmt.formatInt(self.kind, 10, std.fmt.Case.lower, .{}, s.writer());
        try s.concat(",");
        try self.serializeTags(s);
        try s.concat(",");
        try std.json.encodeJsonString(self.content, .{}, s.writer());
        try s.concat("]");
    }

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

test "deserialize and serialize events" {
    var allocator = std.testing.allocator;

    const data =
        \\ {"id":"763644763bd041b621e169c1d9b69ce02cbf300a62d4723d6b7a86d09bed3a49","pubkey":"79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798","created_at":1696961892,"kind":1,"tags":[],"content":"hello from the nostr army knife","sig":"8adce45a11dca7325aa1f99368e24b20197640b28cf599eb17b25ff2e247d032b337957c74b6730f3131824ae8f706241ee4ab4563a98cf4dcc95d0e126ae379"}
    ;
    var event = try deserialize(data, allocator);

    const expected: []const u8 =
        \\{"id":"763644763bd041b621e169c1d9b69ce02cbf300a62d4723d6b7a86d09bed3a49","sig":"8adce45a11dca7325aa1f99368e24b20197640b28cf599eb17b25ff2e247d032b337957c74b6730f3131824ae8f706241ee4ab4563a98cf4dcc95d0e126ae379","pubkey":"79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798","created_at":1696961892,"kind":1,"tags":[],"content":"hello from the nostr army knife"}
    ;
    var buf = string.init(allocator);
    defer buf.deinit();

    try event.serialize(&buf);
    try std.testing.expectEqualStrings(expected, buf.str());
}
