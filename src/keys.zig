const std = @import("std");
const libsecp256k1 = @import("libsecp256k1.zig");

pub const Error = error{ ErrorParsingSecretKey, ErrorSigningMessage };

pub fn parseKey(sk: *[32]u8) Error!SecretKey {
    const ctx = libsecp256k1.getContext();

    var c_keypair: libsecp256k1.secp256k1_keypair = undefined;
    if (0 == libsecp256k1.secp256k1_keypair_create(ctx, &c_keypair, sk)) {
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

    pub fn serializedPublicKey(self: SecretKey, pk: *[32]u8) void {
        var xonly_pk: libsecp256k1.secp256k1_xonly_pubkey = undefined;
        _ = libsecp256k1.secp256k1_keypair_xonly_pub(self.ctx, &xonly_pk, null, &self.keypair);
        _ = libsecp256k1.secp256k1_xonly_pubkey_serialize(self.ctx, pk, &xonly_pk);
        return;
    }

    pub fn sign(self: SecretKey, sig: *[64]u8, msg: [32]u8) Error!void {
        if (0 == libsecp256k1.secp256k1_schnorrsig_sign32(libsecp256k1.getContext(), sig, &msg, &self.keypair, null)) {
            return Error.ErrorSigningMessage;
        }
    }
};
