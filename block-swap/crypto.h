#ifndef __CRYPTO_H__
#define __CRYPTO_H__

#include <stdint.h>

#define CRYPTO_IV_SIZE 12
#define CRYPTO_TAG_SIZE 16

typedef struct Crypto {
    const void *cipher;
    void *ctx;
    void *ctx2;
} Crypto;

void strong_hash(uint8_t *hash, const uint8_t *in, int size);

void crypto_init(Crypto *c);

int encrypt128(Crypto *c, uint8_t *ciphertext, uint8_t *tag, const uint8_t *plaintext, int plaintext_len,
        const uint8_t *key, const uint8_t *iv);

int decrypt128(Crypto *c, uint8_t *plaintext, const uint8_t *ciphertext, int ciphertext_len,
        const uint8_t *tag, const uint8_t *key, const uint8_t *iv);

#endif /* __CRYPTO_H__ */
