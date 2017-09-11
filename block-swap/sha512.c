#include <nettle/sha2.h>

void strong_hash(uint8_t *out, size_t hash_sz, const uint8_t *in, size_t sz)
{
    struct sha512_ctx ctx;
    sha512_init(&ctx);
    sha512_update(&ctx, sz, in);
    sha512_digest(&ctx, hash_sz, out);
}
