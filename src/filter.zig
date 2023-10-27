const std = @import("std");
const assert = @import("std").debug.assert;
const String = @import("string.zig").String;

pub const DeserializationError = error{ UnexpectedToken, UnexpectedValue, TooManyTagItems, TooManyTags };

// letters on the ascii table
const VALID_TAG_FILTER_RANGE_START: u8 = 48; // '0'
const VALID_TAG_FILTER_RANGE_END: u8 = 122; // 'z'
const VALID_TAG_FILTER_SIZE: u8 = VALID_TAG_FILTER_RANGE_END - VALID_TAG_FILTER_RANGE_START + 1; // +1 because it is inclusive on the end

pub fn deserialize(json: []const u8, allocator: std.mem.Allocator) !Filter {
    var scanner = std.json.Scanner.initCompleteInput(allocator, json);
    defer scanner.deinit();

    if (.object_begin != try scanner.next()) return DeserializationError.UnexpectedToken;

    var filter = Filter{
        .tags = TagFilters.init(allocator),
        .allocator = allocator,
    };

    fields: while (true) {
        var name_token: ?std.json.Token = try scanner.nextAlloc(allocator, .alloc_if_needed);

        switch (name_token.?) {
            inline .string, .allocated_string => |name| {
                inline for (.{
                    .{ "ids", "ids" },
                    .{ "authors", "authors" },
                    .{ "#e", "_e" },
                    .{ "#p", "_p" },
                    .{ "#q", "_q" },
                }) |fname| {
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
                                        allocator.free(str);
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
                                    allocator.free(str);
                                }
                                try filter.kinds.?.append(dest);
                            },
                            .array_end => break,
                            else => return DeserializationError.UnexpectedValue,
                        }
                    }
                    continue :fields;
                }

                if (name.len == 2 and name[0] == '#') {
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
                    filter.tags.put(name[1], list);
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
                                allocator.free(str);
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

pub const TagFilters = struct {
    internal: [VALID_TAG_FILTER_SIZE]?std.ArrayList([]u8),
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator) TagFilters {
        var tag_filters: [VALID_TAG_FILTER_SIZE]?std.ArrayList([]u8) = undefined;
        @memset(&tag_filters, null);
        return TagFilters{
            .internal = tag_filters,
            .allocator = allocator,
        };
    }

    pub fn iterator(self: *TagFilters) Iterator {
        return Iterator{ .tag_filters = self };
    }

    pub fn put(self: *TagFilters, char: u8, value: std.ArrayList([]u8)) void {
        assert(char >= VALID_TAG_FILTER_RANGE_START and char <= VALID_TAG_FILTER_RANGE_END);
        self.internal[char - VALID_TAG_FILTER_RANGE_START] = value;
    }

    pub fn get(self: TagFilters, char: u8) ?std.ArrayList([]u8) {
        assert(char >= VALID_TAG_FILTER_RANGE_START and char <= VALID_TAG_FILTER_RANGE_END);
        return self.internal[char - VALID_TAG_FILTER_RANGE_START];
    }

    pub fn delete(self: *TagFilters, char: u8) void {
        assert(char >= VALID_TAG_FILTER_RANGE_START and char <= VALID_TAG_FILTER_RANGE_END);
        self.internal[char - VALID_TAG_FILTER_RANGE_START] = null;
    }

    pub const Entry = struct {
        key: u8,
        value: std.ArrayList([]u8),
    };

    pub const Iterator = struct {
        tag_filters: *TagFilters,
        index: u8 = 0,

        pub fn next(self: *Iterator) ?Entry {
            for (self.index..VALID_TAG_FILTER_SIZE) |i| {
                if (self.tag_filters.internal[i]) |list| {
                    var _i: u8 = @truncate(i);
                    self.index = _i + 1;
                    return Entry{
                        .key = VALID_TAG_FILTER_RANGE_START + _i,
                        .value = list,
                    };
                }
            }
            return null;
        }
    };
};

pub const Filter = struct {
    kinds: ?std.ArrayList(u16) = null,
    ids: ?std.ArrayList([32]u8) = null,
    authors: ?std.ArrayList([32]u8) = null,
    _e: ?std.ArrayList([32]u8) = null, // 'e' tags
    _p: ?std.ArrayList([32]u8) = null, // 'p' tags
    _q: ?std.ArrayList([32]u8) = null, // 'q' tags
    tags: TagFilters,
    since: ?i64 = null,
    until: ?i64 = null,
    limit: ?u16 = null,
    allocator: ?std.mem.Allocator = null,

    pub fn deinit(self: *Filter) void {
        if (self.allocator) |allocator| {
            inline for (.{ "ids", "authors", "kinds", "_e", "_p", "_q" }) |fname| {
                if (@field(self, fname)) |list| {
                    list.deinit();
                }
            }

            var it = self.tags.iterator();
            while (it.next()) |entry| {
                for (entry.value.items) |item| {
                    allocator.free(item);
                }
                entry.value.deinit();
            }
        }
        self.* = undefined;
    }

    pub fn serialize(self: *Filter, allocator: std.mem.Allocator) !String {
        var s = try String.initCapacity(allocator, 500);
        try self.serializeToWriter(&s);
        return s;
    }

    pub fn serializeToWriter(self: *Filter, s: *String) !void {
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

        var it = self.tags.iterator();
        while (it.next()) |entry| {
            empty = false;
            try s.appendSlice("\"#");
            try s.append(entry.key);
            try s.appendSlice("\":[");
            for (entry.value.items) |item| {
                try std.json.encodeJsonString(item, .{}, s.writer());
                try s.append(',');
            }
            _ = s.pop();
            try s.appendSlice("],");
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
        \\{"ids":["2103bc0e14061a0175353cd381502942b46e3a0a2cf8439c57231137b8c9db89"],"authors":["cf473ebe9736ba689c718de3d5ef38909bca57db3c38e3f9de7f5dadfc88ed6f"],"#p":["4477bc0e14061a0175353cd381502942b46e3a0a2cf8439c57231137b8c9e2e2"],"since":9999}
        ,
        \\{"ids":["2103bc0e14061a0175353cd381502942b46e3a0a2cf8439c57231137b8c9db89","2103bc0e14061a0175353cd381502942b46e3a0a2cf8439c57231137b8c9db89","2103bc0e14061a0175353cd381502942b46e3a0a2cf8439c57231137b8c9db89","2103bc0e14061a0175353cd381502942b46e3a0a2cf8439c57231137b8c9db89","2103bc0e14061a0175353cd381502942b46e3a0a2cf8439c57231137b8c9db89","2103bc0e14061a0175353cd381502942b46e3a0a2cf8439c57231137b8c9db89","2103bc0e14061a0175353cd381502942b46e3a0a2cf8439c57231137b8c9db89","2103bc0e14061a0175353cd381502942b46e3a0a2cf8439c57231137b8c9db89","2103bc0e14061a0175353cd381502942b46e3a0a2cf8439c57231137b8c9db89","2103bc0e14061a0175353cd381502942b46e3a0a2cf8439c57231137b8c9db89","2103bc0e14061a0175353cd381502942b46e3a0a2cf8439c57231137b8c9db89","2103bc0e14061a0175353cd381502942b46e3a0a2cf8439c57231137b8c9db89","2103bc0e14061a0175353cd381502942b46e3a0a2cf8439c57231137b8c9db89","2103bc0e14061a0175353cd381502942b46e3a0a2cf8439c57231137b8c9db89"],"authors":["cf473ebe9736ba689c718de3d5ef38909bca57db3c38e3f9de7f5dadfc88ed6f"],"#p":["4477bc0e14061a0175353cd381502942b46e3a0a2cf8439c57231137b8c9e2e2"],"#z":["wwwwzzz"],"since":9999}
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
