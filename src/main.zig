const std = @import("std");
const keys = @import("keys.zig");
const event = @import("event.zig");
const string = @import("string.zig");

test "create keys and sign event" {
    var allocator = std.testing.allocator;

    var input: [32]u8 = [_]u8{ 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32 };

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

    if (evt.verify(allocator)) {
        std.debug.print("valid\n", .{});
    } else |err| switch (err) {
        event.ValidationError.InvalidPublicKey => std.debug.print("invalid public key\n", .{}),
        event.ValidationError.IdDoesntMatch => std.debug.print("id doesn't match\n", .{}),
        event.ValidationError.InvalidSignature => std.debug.print("invalid signature\n", .{}),
        event.ValidationError.InternalError => std.debug.print("internal error\n", .{}),
    }
}
