const std = @import("std");
const String = @import("string.zig").String;

pub fn deserialize(json: []const u8, allocator: std.mem.Allocator) !Filter {
    _ = allocator;
    _ = json;
}

pub const Filter = struct {
    kinds: ?[]u16 = null,
    ids: ?[][32]u8 = null,
    authors: ?[][32]u8 = null,
    _e: ?[][32]u8 = null, // 'e' tags
    _p: ?[][32]u8 = null, // 'p' tags
    tags: ?TagFilters = null,
    since: ?i64 = null,
    until: ?i64 = null,
    limit: ?u16 = null,
    search: ?[]u8 = null,

    pub fn serialize(self: Filter, allocator: std.mem.Allocator) !String {
        var s = try String.initCapacity(allocator, 500);
        try self.serializeToWriter(&s);
        return s;
    }

    pub fn serializeToWriter(self: Filter, s: *String) !void {
        try s.append('{');
        inline for ([_][]const u8{ "ids", "authors", "kinds", "_e", "_p" }) |fname| {
            if (@field(self, fname)) |items| {
                try s.append('"');
                if (fname[0] == '_') {
                    try s.append('#');
                    try s.append(fname[1]);
                } else {
                    try s.appendSlice(fname);
                }
                try s.appendSlice("\":[");
                for (items) |item| {
                    switch (@TypeOf(item)) {
                        inline [32]u8 => {
                            try std.json.encodeJsonString(&std.fmt.bytesToHex(item, std.fmt.Case.lower), .{}, s.writer());
                        },
                        inline u16 => {
                            try std.fmt.formatInt(item, 10, std.fmt.Case.lower, .{}, s.writer());
                        },
                        else => unreachable,
                    }
                    try s.append(',');
                }
                _ = s.pop();
                try s.appendSlice("],");
            }
        }
        inline for ([_][]const u8{ "since", "until", "limit" }) |fname| {
            if (@field(self, fname)) |v| {
                try s.append('"');
                try s.appendSlice(fname);
                try s.appendSlice("\":");
                try std.fmt.formatInt(v, 10, std.fmt.Case.lower, .{}, s.writer());
                try s.append(',');
            }
        }
        if (self.tags) |tags| {
            var it = tags.iterator();
            while (it.next()) |entry| {
                try s.append('"');
                try s.append(entry.key_ptr.*);
                try s.appendSlice("\":[");
                for (entry.value_ptr.*) |item| {
                    try std.json.encodeJsonString(item, .{}, s.writer());
                    try s.append(',');
                }
                _ = s.pop();
                try s.appendSlice("],");
            }
        }
        _ = s.pop();
        try s.append('}');
    }
};

pub const TagFilters = std.HashMap(u8, [][]u8, struct {
    const Self = @This();
    pub fn hash(self: Self, k: u8) u64 {
        _ = self;
        return @intCast(k);
    }
    pub fn eql(self: Self, k1: u8, k2: u8) bool {
        _ = self;
        return k1 == k2;
    }
}, 80);

test "deserialize and serialize filters" {
    const allocator = std.testing.allocator;

    var f: []const u8 = "{\"ids\":[\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"],\"since\":0,\"until\":7777}";

    const id: [32]u8 = undefined;
    var ids = try allocator.alloc([32]u8, 1);
    defer allocator.free(ids);

    ids[0] = id;
    var filter = Filter{ .ids = ids, .since = 0, .until = 7777 };
    var s = try filter.serialize(allocator);
    defer s.deinit();

    try std.testing.expectEqualStrings(f, s.items);
}
