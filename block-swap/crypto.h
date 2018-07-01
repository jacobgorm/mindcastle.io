#ifndef __CRYPTO_H__
#define __CRYPTO_H__

#include <stdint.h>

#include "dubtree_constants.h"

#define CRYPTO_IV_SIZE (96 / 8)
#define CRYPTO_KEY_SIZE (256 / 8)
#define CRYPTO_TAG_SIZE (128 / 8)

typedef struct Crypto {
    const void *cipher;
    void *ctx;
    void *ctx2;
} Crypto;

hash_t strong_hash(const uint8_t *in, int size);

void crypto_init(Crypto *c);

int encrypt256(Crypto *c, uint8_t *ciphertext, uint8_t *tag, const uint8_t *plaintext, int plaintext_len,
        const uint8_t *key, const uint8_t *iv);

int decrypt256(Crypto *c, uint8_t *plaintext, const uint8_t *ciphertext, int ciphertext_len,
        const uint8_t *tag, const uint8_t *key, const uint8_t *iv);

#endif /* __CRYPTO_H__ */
