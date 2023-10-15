const std = @import("std");
const String = @import("string.zig").String;

pub const DeserializationError = error{ UnexpectedToken, UnexpectedValue, TooManyTagItems, TooManyTags };

pub fn deserialize(json: []const u8, allocator: std.mem.Allocator) !Filter {
    var scanner = std.json.Scanner.initCompleteInput(allocator, json);
    defer scanner.deinit();

    if (.object_begin != try scanner.next()) return DeserializationError.UnexpectedToken;

    var filter = Filter{
        .allocator = allocator,
    };

    fields: while (true) {
        var name_token: ?std.json.Token = try scanner.nextAlloc(allocator, .alloc_if_needed);

        switch (name_token.?) {
            inline .string, .allocated_string => |name| {
                inline for (.{ .{ "ids", "ids" }, .{ "authors", "authors" }, .{ "#e", "_e" }, .{ "#p", "_p" }, .{ "#q", "_q" } }) |fname| {
                    if (std.mem.eql(u8, name, fname[0])) {
                        var list = try std.ArrayList([32]u8).initCapacity(allocator, 100);
                        if (.array_begin != try scanner.next()) return DeserializationError.UnexpectedToken;
                        while (true) {
                            const super = try scanner.nextAlloc(allocator, .alloc_if_needed);
                            switch (super) {
                                .string, .allocated_string => |str| {
                                    var dest: [32]u8 = undefined;
                                    _ = try std.fmt.hexToBytes(&dest, str);
                                    if (super == .allocated_string) {
                                        // allocator.free(str);
                                    }
                                    try list.append(dest);
                                },
                                .array_end => break,
                                else => return DeserializationError.UnexpectedValue,
                            }
                        }
                        @field(filter, fname[1]) = list;
                        continue :fields;
                    }
                }

                if (std.mem.eql(u8, name, "kinds")) {
                    filter.kinds = try std.ArrayList(u16).initCapacity(allocator, 100);
                    if (.array_begin != try scanner.next()) return DeserializationError.UnexpectedToken;
                    while (true) {
                        const super = try scanner.nextAlloc(allocator, .alloc_if_needed);
                        switch (super) {
                            .number, .allocated_number => |str| {
                                const dest = try std.fmt.parseInt(u16, str, 10);
                                if (super == .allocated_number) {
                                    // allocator.free(str);
                                }
                                try filter.kinds.?.append(dest);
                            },
                            .array_end => break,
                            else => return DeserializationError.UnexpectedValue,
                        }
                    }
                    continue :fields;
                }

                if (name.len >= 2 and name[0] == '#') {
                    filter.tags = TagFilters.init(allocator);
                    var list = try std.ArrayList([]u8).initCapacity(allocator, 100);
                    if (.array_begin != try scanner.next()) return DeserializationError.UnexpectedToken;
                    while (true) {
                        const super = try scanner.nextAlloc(allocator, .alloc_always);
                        switch (super) {
                            .allocated_string => |str| try list.append(str),
                            .array_end => break,
                            else => return DeserializationError.UnexpectedValue,
                        }
                    }
                    try filter.tags.?.put(name[0..], list);
                    continue :fields;
                }

                inline for ([_][]const u8{ "since", "until", "limit" }) |fname| {
                    if (std.mem.eql(u8, name, fname)) {
                        var val = try scanner.nextAlloc(allocator, .alloc_if_needed);
                        const typ = @typeInfo(@TypeOf(@field(filter, fname))).Optional.child;
                        switch (val) {
                            .number => |str| {
                                @field(filter, fname) = try std.fmt.parseInt(typ, str, 10);
                            },
                            .allocated_number => |str| {
                                @field(filter, fname) = try std.fmt.parseInt(typ, str, 10);
                                // allocator.free(str);
                            },
                            else => return DeserializationError.UnexpectedValue,
                        }
                        continue :fields;
                    }
                }

                // this is an extraneous key in the event object, skip it
                try scanner.skipValue();
            },

            .object_end => break :fields,

            // this might due to malformed json
            else => return DeserializationError.UnexpectedValue,
        }
    }

    return filter;
}

pub const TagFilters = std.StringHashMap(std.ArrayList([]u8));

pub const Filter = struct {
    kinds: ?std.ArrayList(u16) = null,
    ids: ?std.ArrayList([32]u8) = null,
    authors: ?std.ArrayList([32]u8) = null,
    _e: ?std.ArrayList([32]u8) = null, // 'e' tags
    _p: ?std.ArrayList([32]u8) = null, // 'p' tags
    _q: ?std.ArrayList([32]u8) = null, // 'q' tags
    tags: ?TagFilters = null,
    since: ?i64 = null,
    until: ?i64 = null,
    limit: ?u16 = null,
    allocator: ?std.mem.Allocator = null,

    pub fn deinit(self: Filter) void {
        if (self.allocator) |allocator| {
            _ = allocator;
            inline for (.{ "ids", "authors", "kinds", "_e", "_p", "_q" }) |fname| {
                if (@field(self, fname)) |list| {
                    for (list.items) |item| {
                        _ = item;
                        // allocator.free(item);
                    }
                    list.deinit();
                }
            }

            if (self.tags) |tags| {
                var it = tags.iterator();
                while (it.next()) |entry| {
                    for (entry.value_ptr.*.items) |item| {
                        _ = item;
                        // allocator.free(item);
                    }
                }
                // tags.deinit();
            }
        }
    }

    pub fn serialize(self: Filter, allocator: std.mem.Allocator) !String {
        var s = try String.initCapacity(allocator, 500);
        try self.serializeToWriter(&s);
        return s;
    }

    pub fn serializeToWriter(self: Filter, s: *String) !void {
        try s.append('{');
        var empty = true;
        inline for (.{ .{ "ids", "ids" }, .{ "authors", "authors" }, .{ "_e", "#e" }, .{ "_p", "#p" }, .{ "_q", "#q" } }) |fname| {
            if (@field(self, fname[0])) |list| {
                empty = false;
                try s.append('"');
                try s.appendSlice(fname[1]);
                try s.appendSlice("\":[");
                for (list.items) |item| {
                    switch (@TypeOf(item)) {
                        inline [32]u8 => try std.json.encodeJsonString(
                            &std.fmt.bytesToHex(item, std.fmt.Case.lower),
                            .{},
                            s.writer(),
                        ),
                        else => unreachable,
                    }
                    try s.append(',');
                }
                _ = s.pop();
                try s.appendSlice("],");
            }
        }
        if (self.kinds) |kinds| {
            empty = false;
            try s.appendSlice("\"kinds\":[");
            for (kinds.items) |item| {
                switch (@TypeOf(item)) {
                    inline u16 => try std.fmt.formatInt(item, 10, std.fmt.Case.lower, .{}, s.writer()),
                    else => unreachable,
                }
                try s.append(',');
            }
            _ = s.pop();
            try s.appendSlice("],");
        }
        if (self.tags) |tags| {
            var it = tags.iterator();
            while (it.next()) |entry| {
                empty = false;
                try s.appendSlice("\"#");
                try s.appendSlice(entry.key_ptr.*);
                try s.appendSlice("\":[");
                for (entry.value_ptr.*.items) |item| {
                    try std.json.encodeJsonString(item, .{}, s.writer());
                    try s.append(',');
                }
                _ = s.pop();
                try s.appendSlice("],");
            }
        }
        inline for ([_][]const u8{ "since", "until", "limit" }) |fname| {
            if (@field(self, fname)) |v| {
                empty = false;
                try s.append('"');
                try s.appendSlice(fname);
                try s.appendSlice("\":");
                try std.fmt.formatInt(v, 10, std.fmt.Case.lower, .{}, s.writer());
                try s.append(',');
            }
        }
        if (!empty) {
            _ = s.pop();
        }
        try s.append('}');
    }
};

test "deserialize and serialize filters" {
    const allocator = std.testing.allocator;

    const jfilters = [_][]const u8{
        \\{"authors":["cf473ebe9736ba689c718de3d5ef38909bca57db3c38e3f9de7f5dadfc88ed6f"],"limit":12}
        ,
        \\{}
        ,
    };

    for (jfilters) |jfilter| {
        var filter = try deserialize(jfilter, allocator);
        defer filter.deinit();

        var ser = try filter.serialize(allocator);
        defer ser.deinit();
        try std.testing.expectEqualStrings(jfilter, ser.items);
    }
}
