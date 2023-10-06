const std = @import("std");
const keys = @import("keys.zig");

const sha256 = std.crypto.hash.sha2.Sha256;
const Check = std.heap.Check;

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer {
        var x = gpa.deinit();
        switch (x) {
            Check.ok => std.debug.print("ok\n", .{}),
            Check.leak => std.debug.print("has leaked\n", .{}),
        }
    }

    var input: [32]u8 = undefined;
    var n = try std.io.getStdIn().read(&input);
    std.debug.print("input ({}): {}\n", .{ n, std.fmt.fmtSliceHexLower(&input) });

    var sk: [32]u8 = undefined;
    sha256.hash(&input, &sk, .{});
    std.debug.print("private key: {s}\n", .{std.fmt.fmtSliceHexLower(&sk)});

    var pk: [32]u8 = undefined;
    try keys.getPublicKey(&pk, &sk);
    std.debug.print("public key: {s}\n", .{std.fmt.fmtSliceHexLower(&pk)});
}
