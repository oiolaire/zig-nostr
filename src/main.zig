const std = @import("std");
const keys = @import("keys.zig");
const event = @import("event.zig");
const string = @import("string.zig");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer {
        var x = gpa.deinit();
        switch (x) {
            std.heap.Check.ok => std.debug.print("ok\n", .{}),
            std.heap.Check.leak => std.debug.print("has leaked\n", .{}),
        }
    }
    var allocator = gpa.allocator();

    var input: [32]u8 = undefined;
    var n = try std.io.getStdIn().read(&input);
    std.debug.print("input ({}): {}\n", .{ n, std.fmt.fmtSliceHexLower(&input) });

    var skBytes: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(&input, &skBytes, .{});
    std.debug.print("private key: {s}\n", .{std.fmt.fmtSliceHexLower(&skBytes)});

    const sk = try keys.parseKey(&skBytes);
    var pk: [32]u8 = undefined;
    sk.serializedPublicKey(&pk);
    std.debug.print("public key: {s}\n", .{std.fmt.fmtSliceHexLower(&pk)});

    var tags = try allocator.alloc(
        [][]const u8,
        2,
    );
    defer allocator.free(tags);

    var firstTag = try allocator.alloc([]const u8, 2);
    defer allocator.free(firstTag);
    firstTag[0] = "t";
    firstTag[1] = "music";
    tags[0] = firstTag;

    var secondTag = try allocator.alloc([]const u8, 2);
    defer allocator.free(secondTag);
    secondTag[0] = "t";
    secondTag[1] = "prog";
    tags[1] = secondTag;

    var evt: event.Event = .{
        .kind = 1,
        .content = "bandinha nova não é rock progressivo",
        .tags = tags,
    };
    try evt.finalize(sk, allocator);

    var s = string.init(allocator);
    defer s.deinit();
    try evt.serialize(&s);
    std.debug.print("event: {s}\n", .{s.str()});
}
