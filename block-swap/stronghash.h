#ifndef __STRONGHASH_H__
#define __STRONGHASH_H__

#include <stdint.h>

void strong_hash(uint8_t *out, size_t hash_sz, const uint8_t *in, size_t sz);

#endif /* __STRONGHASH_H__ */
