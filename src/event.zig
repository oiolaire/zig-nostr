const std = @import("std");
const assert = @import("std").debug.assert;
const libsecp256k1 = @import("libsecp256k1.zig");
const keys = @import("keys.zig");
const String = @import("string.zig").String;

pub const ValidationError = error{ IdDoesntMatch, InvalidPublicKey, InvalidSignature, InternalError, OutOfMemory };
pub const DeserializationError = error{ UnexpectedToken, UnexpectedValue, TooManyTagItems, TooManyTags };

pub fn deserialize(allocator: std.mem.Allocator, json: []const u8) !Event {
    var scanner = std.json.Scanner.initCompleteInput(allocator, json);
    defer scanner.deinit();

    if (.object_begin != try scanner.next()) return DeserializationError.UnexpectedToken;

    var event = Event{
        .allocator = allocator,
    };
    var missing_fields: u8 = 7;
    fields: while (missing_fields > 0) {
        var name_token: ?std.json.Token = try scanner.nextAlloc(allocator, .alloc_if_needed);

        // assume this field is one that we are expecting -- if it isn't we will add it back in the end
        missing_fields -= 1;

        switch (name_token.?) {
            inline .string, .allocated_string => |name| {
                // id, pubkey and sig are hex values, we will translate these into bytes so
                // we prefer to not have to allocate them if possible (when the result is .string
                // it is just a pointer to the original json buffer)
                inline for ([_][]const u8{ "id", "pubkey", "sig" }) |fname| {
                    if (std.mem.eql(u8, name, fname)) {
                        var val = try scanner.nextAlloc(allocator, .alloc_if_needed);
                        var dest = &@field(event, fname);
                        switch (val) {
                            .string => |str| {
                                _ = try std.fmt.hexToBytes(dest, str);
                            },
                            .allocated_string => |str| {
                                _ = try std.fmt.hexToBytes(dest, str);
                                allocator.free(str);
                            },
                            else => {
                                return DeserializationError.UnexpectedValue;
                            },
                        }
                        continue :fields;
                    }
                }

                // for numbers (kind and created_at) we also don't care to allocate
                // since we have to parse them into integers
                inline for ([_][]const u8{ "kind", "created_at" }) |fname| {
                    if (std.mem.eql(u8, name, fname)) {
                        var val = try scanner.nextAlloc(allocator, .alloc_if_needed);
                        const typ = @TypeOf(@field(event, fname));
                        switch (val) {
                            .number => |str| {
                                @field(event, fname) = try std.fmt.parseInt(typ, str, 10);
                            },
                            .allocated_number => |str| {
                                @field(event, fname) = try std.fmt.parseInt(typ, str, 10);
                                allocator.free(str);
                            },
                            else => {
                                return DeserializationError.UnexpectedValue;
                            },
                        }
                        continue :fields;
                    }
                }

                // content is different, we prefer to allocate because we will need to store
                // and keep track of it anyway.
                if (std.mem.eql(u8, name, "content")) {
                    var val = try scanner.nextAlloc(allocator, .alloc_always);
                    if (val == .allocated_string) {
                        event.content = val.allocated_string;
                    } else {
                        return DeserializationError.UnexpectedValue;
                    }
                    continue :fields;
                }

                // tags is the hardest thing, we will iterate through everything in this complicated setup
                // and we will allocate everything because we must keep everything just like with content
                if (std.mem.eql(u8, name, "tags")) {
                    if (.array_begin != try scanner.next()) return DeserializationError.UnexpectedToken;
                    var tags = try Tags.initCapacity(allocator, 100);

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
                                    try tags.append(tag);
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
                    event.tags = tags;
                    continue :fields;
                }

                // this is an extraneous key in the event object, skip it
                try scanner.skipValue();
            },

            // this might due to malformed json or an event missing fields
            else => return DeserializationError.UnexpectedValue,
        }

        missing_fields += 1; // the field we got wasn't expected
    }

    return event;
}

pub const Tags = std.ArrayList(Tag);
pub const Tag = std.ArrayList([]const u8);

pub const Event = struct {
    kind: u16 = 1,
    content: []const u8 = &.{},
    tags: ?Tags = null,
    created_at: i64 = undefined,
    pubkey: [32]u8 = undefined,
    id: [32]u8 = undefined,
    sig: [64]u8 = undefined,
    allocator: ?std.mem.Allocator = null,

    pub fn deinit(self: *Event) void {
        if (self.allocator) |allocator| {
            allocator.free(self.content);

            if (self.tags) |tags| {
                for (tags.items) |tag| {
                    for (tag.items) |item| {
                        allocator.free(item);
                    }
                    tag.deinit();
                }
                tags.deinit();
            }
        }
        self.* = undefined;
    }

    pub fn verify(self: Event, allocator: std.mem.Allocator) ValidationError!void {
        // check id
        var ser = self.serializeForHashing(allocator) catch |err| switch (err) {
            error.OutOfMemory => return ValidationError.InternalError,
        };
        defer ser.deinit();

        var id: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(ser.items, &id, .{});
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

    pub fn finalize(self: *Event, allocator: std.mem.Allocator, sk: keys.SecretKey) !void {
        // set created_at if not set
        self.created_at = std.time.timestamp();

        // write public key
        self.pubkey = sk.serializedPublicKey();

        // serialize and hash the event to obtain the id
        var ser = try self.serializeForHashing(allocator);
        defer ser.deinit();
        std.crypto.hash.sha2.Sha256.hash(ser.items, &self.id, .{});

        // fill in the signature
        self.sig = try sk.sign(self.id);
    }

    pub fn serialize(self: *Event, allocator: std.mem.Allocator) !String {
        var s = try String.initCapacity(allocator, "'id''','pubkey''','sig''','content''','tags'[],'kind'~~~~~,'created_at'~~~~~~~~~~,".len + 128 + 64 + 64 + self.content.len);
        try s.appendSlice("{\"id\":");
        try std.json.encodeJsonString(&std.fmt.bytesToHex(self.id, std.fmt.Case.lower), .{}, s.writer());
        try s.appendSlice(",\"pubkey\":");
        try std.json.encodeJsonString(&std.fmt.bytesToHex(self.pubkey, std.fmt.Case.lower), .{}, s.writer());
        try s.appendSlice(",\"created_at\":");
        try std.fmt.formatInt(self.created_at, 10, std.fmt.Case.lower, .{}, s.writer());
        try s.appendSlice(",\"kind\":");
        try std.fmt.formatInt(self.kind, 10, std.fmt.Case.lower, .{}, s.writer());
        try s.appendSlice(",\"tags\":");
        try self.serializeTags(&s);
        try s.appendSlice(",\"content\":");
        try std.json.encodeJsonString(self.content, .{}, s.writer());
        try s.appendSlice(",\"sig\":");
        try std.json.encodeJsonString(&std.fmt.bytesToHex(self.sig, std.fmt.Case.lower), .{}, s.writer());
        try s.append('}');
        return s;
    }

    fn serializeForHashing(self: Event, allocator: std.mem.Allocator) !String {
        var s = try String.initCapacity(allocator, "[0,'',,,[],'']".len + 64 + self.content.len);
        try s.appendSlice("[0,");
        try std.json.encodeJsonString(&std.fmt.bytesToHex(self.pubkey, std.fmt.Case.lower), .{}, s.writer());
        try s.append(',');
        try std.fmt.formatInt(self.created_at, 10, std.fmt.Case.lower, .{}, s.writer());
        try s.append(',');
        try std.fmt.formatInt(self.kind, 10, std.fmt.Case.lower, .{}, s.writer());
        try s.append(',');
        try self.serializeTags(&s);
        try s.append(',');
        try std.json.encodeJsonString(self.content, .{}, s.writer());
        try s.append(']');
        return s;
    }

    fn serializeTags(self: Event, w: *String) !void {
        try w.append('[');
        if (self.tags) |tags| {
            for (tags.items, 0..) |tag, t| {
                if (t != 0) {
                    try w.append(',');
                }
                try w.append('[');
                for (tag.items, 0..) |item, i| {
                    if (i != 0) {
                        try w.append(',');
                    }
                    try std.json.encodeJsonString(item, .{}, w.writer());
                }
                try w.append(']');
            }
        }
        try w.append(']');
    }
};

test "deserialize and serialize events" {
    var allocator = std.testing.allocator;

    const jevents = [_][]const u8{
        \\{"id":"763644763bd041b621e169c1d9b69ce02cbf300a62d4723d6b7a86d09bed3a49","pubkey":"79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798","created_at":1696961892,"kind":27622,"tags":[],"content":"maçã\n\n\"verde\"","sig":"8adce45a11dca7325aa1f99368e24b20197640b28cf599eb17b25ff2e247d032b337957c74b6730f3131824ae8f706241ee4ab4563a98cf4dcc95d0e126ae379"}
        ,
        \\{"id":"440cd22bce7c5d8682522678bdcaa120e0efd821a7cad6d4b621558a386316a3","pubkey":"79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798","created_at":1697155143,"kind":1,"tags":[["s","qwmke","asn"],["xxx","xxx","xxx","xxx"],["z","s"]],"content":"skdlhsalkdsakdbsalkdbsakdbskdlhsalkdsakdbsalkdbsakdbskdlhsalkdsakdbsalkdbsakdbskdlhsalkdsakdbsalkdbsakdbskdlhsalkdsakdbsalkdbsakdbskdlhsalkdsakdbsalkdbsakdbskdlhsalkdsakdbsalkdbsakdbskdlhsalkdsakdbsalkdbsakdbskdlhsalkdsakdbsalkdbsakdbskdlhsalkdsakdbsalkdbsakdbskdlhsalkdsakdbsalkdbsakdbskdlhsalkdsakdbsalkdbsakdbskdlhsalkdsakdbsalkdbsakdbskdlhsalkdsakdbsalkdbsakdbskdlhsalkdsakdbsalkdbsakdbskdlhsalkdsakdbsalkdbsakdbskdlhsalkdsakdbsalkdbsakdbskdlhsalkdsakdbsalkdbsakdbskdlhsalkdsakdbsalkdbsakdbskdlhsalkdsakdbsalkdbsakdbskdlhsalkdsakdbsalkdbsakdbskdlhsalkdsakdbsalkdbsakdbskdlhsalkdsakdbsalkdbsakdbskdlhsalkdsakdbsalkdbsakdbskdlhsalkdsakdbsalkdbsakdbskdlhsalkdsakdbsalkdbsakdbskdlhsalkdsakdbsalkdbsakdbskdlhsalkdsakdbsalkdbsakdbskdlhsalkdsakdbsalkdbsakdbskdlhsalkdsakdbsalkdbsakdbskdlhsalkdsakdbsalkdbsakdbskdlhsalkdsakdbsalkdbsakdbskdlhsalkdsakdbsalkdbsakdbskdlhsalkdsakdbsalkdbsakdbskdlhsalkdsakdbsalkdbsakdbskdlhsalkdsakdbsalkdbsakdbskdlhsalkdsakdbsalkdbsakdbskdlhsalkdsakdbsalkdbsakdbskdlhsalkdsakdbsalkdbsakdbskdlhsalkdsakdbsalkdbsakdbskdlhsalkdsakdbsalkdbsakdbskdlhsalkdsakdbsalkdbsakdbskdlhsalkdsakdbsalkdbsakdbskdlhsalkdsakdbsalkdbsakdbskdlhsalkdsakdbsalkdbsakdbskdlhsalkdsakdbsalkdbsakdbskdlhsalkdsakdbsalkdbsakdbskdlhsalkdsakdbsalkdbsakdbskdlhsalkdsakdbsalkdbsakdbskdlhsalkdsakdbsalkdbsakdbskdlhsalkdsakdbsalkdbsakdbskdlhsalkdsakdbsalkdbsakdbskdlhsalkdsakdbsalkdbsakdbskdlhsalkdsakdbsalkdbsakdbskdlhsalkdsakdbsalkdbsakdbskdlhsalkdsakdbsalkdbsakdbskdlhsalkdsakdbsalkdbsakdbskdlhsalkdsakdbsalkdbsakdbskdlhsalkdsakdbsalkdbsakdbskdlhsalkdsakdbsalkdbsakdbskdlhsalkdsakdbsalkdbsakdbskdlhsalkdsakdbsalkdbsakdbskdlhsalkdsakdbsalkdbsakdbskdlhsalkdsakdbsalkdbsakdbskdlhsalkdsakdbsalkdbsakdbskdlhsalkdsakdbsalkdbsakdbskdlhsalkdsakdbsalkdbsakdbskdlhsalkdsakdbsalkdbsakdbskdlhsalkdsakdbsalkdbsakdbskdlhsalkdsakdbsalkdbsakdbskdlhsalkdsakdbsalkdbsakdbskdlhsalkdsakdbsalkdbsakdbskdlhsalkdsakdbsalkdbsakdbskdlhsalkdsakdbsalkdbsakdbskdlhsalkdsakdbsalkdbsakdbskdlhsalkdsakdbsalkdbsakdbskdlhsalkdsakdbsalkdbsakdbskdlhsalkdsakdbsalkdbsakdbskdlhsalkdsakdbsalkdbsakdbskdlhsalkdsakdbsalkdbsakdbskdlhsalkdsakdbsalkdbsakdbskdlhsalkdsakdbsalkdbsakdbskdlhsalkdsakdbsalkdbsakdbskdlhsalkdsakdbsalkdbsakdb","sig":"0b51c4470b51c578e1305db7420587f25c20986f63b9c51f10422780e4bb35671c1f09cb7bdd6f0dea029551866cca8ec95c7d0d29e2020efb54e21d59e8d7ce"}
        ,
    };

    for (jevents) |jevent| {
        var event = try deserialize(allocator, jevent);
        defer event.deinit();

        var ser = try event.serialize(allocator);
        defer ser.deinit();
        try std.testing.expectEqualStrings(jevent, ser.items);
    }
}

test "deserialize and serialize an event with extra fields" {
    var allocator = std.testing.allocator;

    const jevent =
        \\{"id":"20849298f112b9528b1dfde321ca80499654a8222fb81df7e46dca78cd922f45","pubkey":"79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798","created_at":1697310467,"kind":17,"random":"quwheo87321g48eivbad","other_stuff":{"zzz": {"_": [null, true, [], 8998]}},"tags":[[],["A"]],"content":"","sig":"29dafa46e275385cc557f8d69c4ed97a20b5e3b494a845432dac49e8393770b2953a731476bd714959538b5956264e97db868fba9ce81b939dcb8d1adf12eef6"}
    ;
    const jevent_expected =
        \\{"id":"20849298f112b9528b1dfde321ca80499654a8222fb81df7e46dca78cd922f45","pubkey":"79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798","created_at":1697310467,"kind":17,"tags":[[],["A"]],"content":"","sig":"29dafa46e275385cc557f8d69c4ed97a20b5e3b494a845432dac49e8393770b2953a731476bd714959538b5956264e97db868fba9ce81b939dcb8d1adf12eef6"}
    ;

    var event = try deserialize(allocator, jevent);
    defer event.deinit();

    var ser = try event.serialize(allocator);
    defer ser.deinit();
    try std.testing.expectEqualStrings(jevent_expected, ser.items);
}

test "create an event and sign it" {
    var allocator = std.testing.allocator;

    var evt = Event{
        .kind = 1,
        .content = try allocator.dupe(u8, "hello world"),
        .tags = try Tags.initCapacity(allocator, 5),
        .allocator = allocator,
    };
    var tag = try Tag.initCapacity(allocator, 2);
    tag.appendAssumeCapacity(try allocator.dupe(u8, "t"));
    tag.appendAssumeCapacity(try allocator.dupe(u8, "spam"));
    evt.tags.?.appendAssumeCapacity(tag);
    defer evt.deinit();

    try evt.finalize(
        allocator,
        keys.parseKey([32]u8{ 11, 12, 13, 14, 15, 16, 17, 18, 19, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 123, 124, 125, 126, 127, 128, 129, 130, 131, 132 }) catch unreachable,
    );

    try evt.verify(allocator);
}
