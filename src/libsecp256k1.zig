const c = @cImport({
    @cInclude("secp256k1.h");
    @cInclude("secp256k1_extrakeys.h");
    @cInclude("secp256k1_schnorrsig.h");
});

pub usingnamespace c;

const FLAGS_TYPE_CONTEXT = 1 << 0;
const FLAGS_BIT_CONTEXT_VERIFY = 1 << 8;
const FLAGS_BIT_CONTEXT_SIGN = 1 << 9;
const FLAGS_TYPE_COMPRESSION = 1 << 1;
const FLAGS_BIT_COMPRESSION = 1 << 8;

pub const CONTEXT_VERIFY = (FLAGS_TYPE_CONTEXT | FLAGS_BIT_CONTEXT_VERIFY);
pub const CONTEXT_SIGN = (FLAGS_TYPE_CONTEXT | FLAGS_BIT_CONTEXT_SIGN);
pub const EC_COMPRESSED = (FLAGS_TYPE_COMPRESSION | FLAGS_BIT_COMPRESSION);

pub var ctx: *c.secp256k1_context = undefined;
var contextCreated = false;

pub fn getContext() *c.secp256k1_context {
    if (!contextCreated) {
        ctx = c.secp256k1_context_create(CONTEXT_SIGN | CONTEXT_VERIFY) orelse unreachable;
        contextCreated = true;
    }
    return ctx;
}
