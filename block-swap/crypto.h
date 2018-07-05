#ifndef __CRYPTO_H__
#define __CRYPTO_H__

#include <stdint.h>

#include "dubtree_constants.h"

typedef struct Crypto {
    uint8_t *key;
    const void *cipher;
    void *ctx;
} Crypto;

void crypto_init(Crypto *c, uint8_t *key);
void crypto_close(Crypto *crypto);

int encrypt256(Crypto *c, uint8_t *ciphertext, uint8_t *tag, const uint8_t *plaintext, int plaintext_len,
        const uint8_t *iv);

int decrypt256(Crypto *c, uint8_t *plaintext, const uint8_t *ciphertext, int ciphertext_len,
        const uint8_t *tag, const uint8_t *iv);

#endif /* __CRYPTO_H__ */
