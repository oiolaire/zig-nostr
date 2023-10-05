const c = @cImport(@cInclude("secp256k1.h"));
const std = @import("std");
const sha256 = std.crypto.hash.sha2.Sha256;
const Check = std.heap.Check;

const FLAGS_TYPE_CONTEXT = 1 << 0;
const FLAGS_BIT_CONTEXT_VERIFY = 1 << 8;
const FLAGS_BIT_CONTEXT_SIGN = 1 << 9;
const FLAGS_TYPE_COMPRESSION = 1 << 1;
const FLAGS_BIT_COMPRESSION = 1 << 8;

const CONTEXT_VERIFY = (FLAGS_TYPE_CONTEXT | FLAGS_BIT_CONTEXT_VERIFY);
const CONTEXT_SIGN = (FLAGS_TYPE_CONTEXT | FLAGS_BIT_CONTEXT_SIGN);
const EC_COMPRESSED = (FLAGS_TYPE_COMPRESSION | FLAGS_BIT_COMPRESSION);
const EC_UNCOMPRESSED = (FLAGS_TYPE_COMPRESSION);

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

    var c_pk: c.secp256k1_pubkey = undefined;
    var ctx = c.secp256k1_context_create(CONTEXT_SIGN | CONTEXT_VERIFY);
    if (c.secp256k1_ec_pubkey_create(ctx, &c_pk, &sk) == 0) {
        std.debug.print("error creating pubkey\n", .{});
        return;
    }

    var size: usize = 33;
    var pk: [33]u8 = undefined;
    if (c.secp256k1_ec_pubkey_serialize(ctx, &pk, &size, &c_pk, EC_COMPRESSED) == 0) {
        std.debug.print("error serializing pubkey\n", .{});
        return;
    }
    std.debug.print("public key ({d}): {s}\n", .{ size, std.fmt.fmtSliceHexLower(&pk) });
}
