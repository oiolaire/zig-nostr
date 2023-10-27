const std = @import("std");
const libsecp256k1 = @import("libsecp256k1.zig");

pub const Error = error{ ErrorParsingSecretKey, ErrorSigningMessage };

pub fn parseKey(sk: [32]u8) Error!SecretKey {
    const ctx = libsecp256k1.getContext();

    var c_keypair: libsecp256k1.secp256k1_keypair = undefined;
    if (0 == libsecp256k1.secp256k1_keypair_create(ctx, &c_keypair, &sk)) {
        return Error.ErrorParsingSecretKey;
    }

    return SecretKey{
        .ctx = ctx,
        .keypair = c_keypair,
    };
}

pub const SecretKey = struct {
    ctx: *libsecp256k1.secp256k1_context,
    keypair: libsecp256k1.secp256k1_keypair,

    pub fn serializedPublicKey(self: SecretKey) [32]u8 {
        var pk: [32]u8 = undefined;
        var xonly_pk: libsecp256k1.secp256k1_xonly_pubkey = undefined;
        _ = libsecp256k1.secp256k1_keypair_xonly_pub(self.ctx, &xonly_pk, null, &self.keypair);
        _ = libsecp256k1.secp256k1_xonly_pubkey_serialize(self.ctx, &pk, &xonly_pk);
        return pk;
    }

    pub fn sign(self: SecretKey, msg: [32]u8) Error![64]u8 {
        var sig: [64]u8 = undefined;
        if (0 == libsecp256k1.secp256k1_schnorrsig_sign32(
            libsecp256k1.getContext(),
            &sig,
            &msg,
            &self.keypair,
            null,
        )) {
            return Error.ErrorSigningMessage;
        }

        return sig;
    }
};

test "parse private key and generate public key" {
    var input: [32]u8 = [_]u8{ 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32 };

    var skBytes: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(&input, &skBytes, .{});

    var skExpected: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&skExpected, "ae216c2ef5247a3782c135efa279a3e4cdc61094270f5d2be58c6204b7a612c9");
    try std.testing.expectEqualSlices(u8, &skExpected, &skBytes);

    const sk = try parseKey(skBytes);
    var pk = sk.serializedPublicKey();

    var pkExpected: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&pkExpected, "735136c080052241a55d448abc44c453959515d275003e47147f8eb51e965c0b");
    try std.testing.expectEqualSlices(u8, &pkExpected, &pk);
}
