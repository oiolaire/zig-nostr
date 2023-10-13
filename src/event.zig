const std = @import("std");
const libsecp256k1 = @import("libsecp256k1.zig");
const keys = @import("keys.zig");
const string = @import("string.zig");

pub const ValidationError = error{ IdDoesntMatch, InvalidPublicKey, InvalidSignature, InternalError };
pub const DeserializationError = error{ UnexpectedToken, UnexpectedValue, TooManyTagItems, TooManyTags };

pub fn deserialize(json: []const u8, allocator: std.mem.Allocator) !Event {
    var scanner = std.json.Scanner.initCompleteInput(allocator, json);
    defer scanner.deinit();

    if (.object_begin != try scanner.next()) return DeserializationError.UnexpectedToken;

    var event = Event{
        .allocator = allocator,
    };
    var missing_fields: u8 = 7;
    while (missing_fields > 0) {
        var name_token: ?std.json.Token = try scanner.nextAlloc(allocator, .alloc_if_needed);
        switch (name_token.?) {
            inline .string, .allocated_string => |name| {
                // id, pubkey and sig are hex values, we will translate these into bytes so
                // we prefer to not have to allocate them if possible (when the result is .string
                // it is just a pointer to the original json buffer)
                if (std.mem.eql(u8, name, "id")) {
                    var val = try scanner.nextAlloc(allocator, .alloc_if_needed);
                    switch (val) {
                        .string => |str| {
                            _ = try std.fmt.hexToBytes(&event.id, str);
                        },
                        .allocated_string => |str| {
                            _ = try std.fmt.hexToBytes(&event.id, str);
                            allocator.free(str);
                        },
                        else => {
                            return DeserializationError.UnexpectedValue;
                        },
                    }
                } else if (std.mem.eql(u8, name, "pubkey")) {
                    var val = try scanner.nextAlloc(allocator, .alloc_if_needed);
                    switch (val) {
                        .string => |str| {
                            _ = try std.fmt.hexToBytes(&event.pubkey, str);
                        },
                        .allocated_string => |str| {
                            _ = try std.fmt.hexToBytes(&event.pubkey, str);
                            allocator.free(str);
                        },
                        else => {
                            return DeserializationError.UnexpectedValue;
                        },
                    }
                } else if (std.mem.eql(u8, name, "sig")) {
                    var val = try scanner.nextAlloc(allocator, .alloc_if_needed);
                    switch (val) {
                        .string => |str| {
                            _ = try std.fmt.hexToBytes(&event.sig, str);
                        },
                        .allocated_string => |str| {
                            _ = try std.fmt.hexToBytes(&event.sig, str);
                            allocator.free(str);
                        },
                        else => {
                            return DeserializationError.UnexpectedValue;
                        },
                    }
                } else if (std.mem.eql(u8, name, "content")) {
                    // content is different, we prefer to allocate because we will need to store
                    // and keep track of it anyway.
                    var val = try scanner.nextAlloc(allocator, .alloc_always);
                    if (val == .allocated_string) {
                        event.content = val.allocated_string;
                    } else {
                        return DeserializationError.UnexpectedValue;
                    }
                } else if (std.mem.eql(u8, name, "kind")) {
                    // for numbers (kind and created_at) we also don't care to allocate
                    // since we have to parse them into integers
                    var val = try scanner.nextAlloc(allocator, .alloc_if_needed);
                    switch (val) {
                        .number => |str| {
                            event.kind = try std.fmt.parseInt(u16, str, 10);
                        },
                        .allocated_number => |str| {
                            event.kind = try std.fmt.parseInt(u16, str, 10);
                            allocator.free(str);
                        },
                        else => {
                            return DeserializationError.UnexpectedValue;
                        },
                    }
                } else if (std.mem.eql(u8, name, "created_at")) {
                    var val = try scanner.nextAlloc(allocator, .alloc_if_needed);
                    switch (val) {
                        .number => |str| {
                            event.created_at = try std.fmt.parseInt(i64, str, 10);
                        },
                        .allocated_number => |str| {
                            event.created_at = try std.fmt.parseInt(i64, str, 10);
                            allocator.free(str);
                        },
                        else => {
                            return DeserializationError.UnexpectedValue;
                        },
                    }
                } else if (std.mem.eql(u8, name, "tags")) {
                    // tags is the hardest thing, we will iterate through everything in this complicated setup
                    // and we will allocate everything because we must keep everything just like with content
                    if (.array_begin != try scanner.next()) return DeserializationError.UnexpectedToken;
                    event.tags = try Tags.initCapacity(allocator, 100);

                    var tag_open = false;
                    var tag: Tag = undefined;
                    while (true) {
                        // we will allocate these and keep track of them
                        switch (try scanner.nextAlloc(allocator, .alloc_always)) {
                            .array_begin => {
                                if (tag_open) {
                                    // can't have arrays inside tags
                                    return DeserializationError.UnexpectedValue;
                                }

                                // initializing a tag
                                tag_open = true;
                                tag = try Tag.initCapacity(allocator, 10);
                            },
                            .array_end => {
                                if (tag_open) {
                                    // closing a tag
                                    tag_open = false;

                                    // take only the items that were filled in this tag
                                    try event.tags.append(tag);
                                } else {
                                    // closing the tags list
                                    break;
                                }
                            },
                            .allocated_string => |v| {
                                if (!tag_open) {
                                    // can't have a loose string inside the tags array
                                    return DeserializationError.UnexpectedValue;
                                }

                                // an item inside a tag
                                try tag.append(v);
                            },
                            else => {
                                // this is not a valid tag
                                return DeserializationError.UnexpectedValue;
                            },
                        }
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

pub const Tags = std.ArrayList(Tag);
pub const Tag = std.ArrayList([]u8);

pub const Event = struct {
    kind: u16 = 1,
    content: []const u8 = &.{},
    tags: Tags = undefined,
    created_at: i64 = undefined,
    pubkey: [32]u8 = undefined,
    id: [32]u8 = undefined,
    sig: [64]u8 = undefined,
    allocator: std.mem.Allocator = undefined,

    pub fn deinit(self: Event) void {
        self.allocator.free(self.content);

        for (self.tags.items) |tag| {
            for (tag.items) |item| {
                self.allocator.free(item);
            }
            tag.deinit();
        }
        self.tags.deinit();
    }

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
        try s.concat(",\"sig\":");
        try std.json.encodeJsonString(&std.fmt.bytesToHex(self.sig, std.fmt.Case.lower), .{}, s.writer());
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
        for (self.tags.items, 0..) |tag, t| {
            if (t != 0) {
                try w.concat(",");
            }
            try w.concat("[");
            for (tag.items, 0..) |item, i| {
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

    const jevents = [_][]const u8{
        \\{"id":"763644763bd041b621e169c1d9b69ce02cbf300a62d4723d6b7a86d09bed3a49","pubkey":"79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798","created_at":1696961892,"kind":1,"tags":[],"content":"hello from the nostr army knife","sig":"8adce45a11dca7325aa1f99368e24b20197640b28cf599eb17b25ff2e247d032b337957c74b6730f3131824ae8f706241ee4ab4563a98cf4dcc95d0e126ae379"}
        ,
        \\{"id":"440cd22bce7c5d8682522678bdcaa120e0efd821a7cad6d4b621558a386316a3","pubkey":"79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798","created_at":1697155143,"kind":1,"tags":[["s","qwmke","asn"],["xxx","xxx","xxx","xxx"],["z","s"]],"content":"skdlhsalkdsakdbsalkdbsakdbskdlhsalkdsakdbsalkdbsakdbskdlhsalkdsakdbsalkdbsakdbskdlhsalkdsakdbsalkdbsakdbskdlhsalkdsakdbsalkdbsakdbskdlhsalkdsakdbsalkdbsakdbskdlhsalkdsakdbsalkdbsakdbskdlhsalkdsakdbsalkdbsakdbskdlhsalkdsakdbsalkdbsakdbskdlhsalkdsakdbsalkdbsakdbskdlhsalkdsakdbsalkdbsakdbskdlhsalkdsakdbsalkdbsakdbskdlhsalkdsakdbsalkdbsakdbskdlhsalkdsakdbsalkdbsakdbskdlhsalkdsakdbsalkdbsakdbskdlhsalkdsakdbsalkdbsakdbskdlhsalkdsakdbsalkdbsakdbskdlhsalkdsakdbsalkdbsakdbskdlhsalkdsakdbsalkdbsakdbskdlhsalkdsakdbsalkdbsakdbskdlhsalkdsakdbsalkdbsakdbskdlhsalkdsakdbsalkdbsakdbskdlhsalkdsakdbsalkdbsakdbskdlhsalkdsakdbsalkdbsakdbskdlhsalkdsakdbsalkdbsakdbskdlhsalkdsakdbsalkdbsakdbskdlhsalkdsakdbsalkdbsakdbskdlhsalkdsakdbsalkdbsakdbskdlhsalkdsakdbsalkdbsakdbskdlhsalkdsakdbsalkdbsakdbskdlhsalkdsakdbsalkdbsakdbskdlhsalkdsakdbsalkdbsakdbskdlhsalkdsakdbsalkdbsakdbskdlhsalkdsakdbsalkdbsakdbskdlhsalkdsakdbsalkdbsakdbskdlhsalkdsakdbsalkdbsakdbskdlhsalkdsakdbsalkdbsakdbskdlhsalkdsakdbsalkdbsakdbskdlhsalkdsakdbsalkdbsakdbskdlhsalkdsakdbsalkdbsakdbskdlhsalkdsakdbsalkdbsakdbskdlhsalkdsakdbsalkdbsakdbskdlhsalkdsakdbsalkdbsakdbskdlhsalkdsakdbsalkdbsakdbskdlhsalkdsakdbsalkdbsakdbskdlhsalkdsakdbsalkdbsakdbskdlhsalkdsakdbsalkdbsakdbskdlhsalkdsakdbsalkdbsakdbskdlhsalkdsakdbsalkdbsakdbskdlhsalkdsakdbsalkdbsakdbskdlhsalkdsakdbsalkdbsakdbskdlhsalkdsakdbsalkdbsakdbskdlhsalkdsakdbsalkdbsakdbskdlhsalkdsakdbsalkdbsakdbskdlhsalkdsakdbsalkdbsakdbskdlhsalkdsakdbsalkdbsakdbskdlhsalkdsakdbsalkdbsakdbskdlhsalkdsakdbsalkdbsakdbskdlhsalkdsakdbsalkdbsakdbskdlhsalkdsakdbsalkdbsakdbskdlhsalkdsakdbsalkdbsakdbskdlhsalkdsakdbsalkdbsakdbskdlhsalkdsakdbsalkdbsakdbskdlhsalkdsakdbsalkdbsakdbskdlhsalkdsakdbsalkdbsakdbskdlhsalkdsakdbsalkdbsakdbskdlhsalkdsakdbsalkdbsakdbskdlhsalkdsakdbsalkdbsakdbskdlhsalkdsakdbsalkdbsakdbskdlhsalkdsakdbsalkdbsakdbskdlhsalkdsakdbsalkdbsakdbskdlhsalkdsakdbsalkdbsakdbskdlhsalkdsakdbsalkdbsakdbskdlhsalkdsakdbsalkdbsakdbskdlhsalkdsakdbsalkdbsakdbskdlhsalkdsakdbsalkdbsakdbskdlhsalkdsakdbsalkdbsakdbskdlhsalkdsakdbsalkdbsakdbskdlhsalkdsakdbsalkdbsakdbskdlhsalkdsakdbsalkdbsakdbskdlhsalkdsakdbsalkdbsakdbskdlhsalkdsakdbsalkdbsakdbskdlhsalkdsakdbsalkdbsakdbskdlhsalkdsakdbsalkdbsakdb","sig":"0b51c4470b51c578e1305db7420587f25c20986f63b9c51f10422780e4bb35671c1f09cb7bdd6f0dea029551866cca8ec95c7d0d29e2020efb54e21d59e8d7ce"}
        ,
    };

    for (jevents) |jevent| {
        var event = try deserialize(jevent, allocator);
        defer event.deinit();

        var buf = string.init(allocator);
        defer buf.deinit();

        try event.serialize(&buf);
        try std.testing.expectEqualStrings(jevent, buf.str());
    }
}
