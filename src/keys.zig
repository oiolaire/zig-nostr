const std = @import("std");
const c = @cImport(@cInclude("secp256k1.h"));
const libsecp256k1 = @import("libsecp256k1.zig");

const KeyCreationError = error{ ErrorSerializingPublicKey, ErrorCreatingPublicKey };

pub fn get_public_key(pk: *[32]u8, sk: *[32]u8) KeyCreationError!void {
    var c_pk: c.secp256k1_pubkey = undefined;
    var ctx = c.secp256k1_context_create(libsecp256k1.CONTEXT_SIGN);
    if (c.secp256k1_ec_pubkey_create(ctx, &c_pk, sk) == 0) {
        return KeyCreationError.ErrorCreatingPublicKey;
    }

    var size: usize = 33;
    var compressed_pk: [33]u8 = undefined;
    if (c.secp256k1_ec_pubkey_serialize(ctx, &compressed_pk, &size, &c_pk, libsecp256k1.EC_COMPRESSED) == 0) {
        return KeyCreationError.ErrorSerializingPublicKey;
    }

    std.mem.copy(u8, pk, compressed_pk[1..33]);
    return;
}
