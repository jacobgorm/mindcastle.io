#include <blake2.h>

void strong_hash(uint8_t *out, size_t hash_sz, const uint8_t *in, size_t sz)
{
    blake2b_state s;
    blake2b_init(&s, hash_sz);
    blake2b_update(&s, in, sz);
    blake2b_final(&s, out, hash_sz);
}
