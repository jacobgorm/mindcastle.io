#include <assert.h>
#include <openssl/aes.h>
#include <openssl/sha.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <string.h>
#include <err.h>

#include "dubtree_constants.h"
#include "crypto.h"

hash_t strong_hash(const uint8_t *in, int size)
{
    uint8_t tmp[512 / 8];
    hash_t hash;
    SHA512(in, size, tmp);
    memcpy(hash.bytes, tmp, sizeof(hash.bytes));
    return hash;
}


__attribute__((constructor)) static void crypto_global_init(void)
{
    printf("loading random seed...\n");
    if (RAND_load_file("/dev/random", 32) != 32) {
        errx(1, "RAND_load_file failed");
    }
}

void crypto_init(Crypto *crypto, uint8_t *key)
{
    if (!(crypto->cipher = EVP_aes_256_gcm())) {
        errx(1, "EVP_aes_256_gcm failed");
    }
    if (!(crypto->ctx = EVP_CIPHER_CTX_new())) {
        errx(1, "EVP_CIPHER_CTX_new failed");
    }
    if (!(crypto->ctx2 = EVP_CIPHER_CTX_new())) {
        errx(1, "EVP_CIPHER_CTX_new failed");
    }
    crypto->key = key; /* by reference to avoid many copies of key in memory. */
}

int encrypt256(Crypto *crypto, uint8_t *ciphertext, uint8_t *tag,
        const uint8_t *plaintext, int plaintext_len, const uint8_t *iv)
{
    const EVP_CIPHER *cipher = crypto->cipher;
    EVP_CIPHER_CTX *ctx = crypto->ctx;

    int len;
    int ciphertext_len = 0;

    assert(crypto && crypto->key);
    if (EVP_EncryptInit_ex(ctx, cipher, NULL, crypto->key, iv) != 1) {
        errx(1, "EVP_EncryptInit_ex failed");
    }

    if (EVP_EncryptUpdate(ctx, ciphertext + ciphertext_len, &len, plaintext, plaintext_len) != 1) {
        errx(1, "EVP_EncryptUpdate failed");
    }
    ciphertext_len += len;

    if (EVP_EncryptFinal_ex(ctx, ciphertext + ciphertext_len, &len) != 1) {
        errx(1, "EVP_EncryptFinal_ex failed");
    }
    ciphertext_len += len;
    
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, CRYPTO_TAG_SIZE, tag) != 1) {
        errx(1, "EVP_EncryptFinal_ex failed");
    }

    EVP_CIPHER_CTX_reset(ctx);

    return ciphertext_len;
}

int decrypt256(Crypto *crypto, uint8_t *plaintext, const uint8_t *ciphertext,
        int ciphertext_len, const uint8_t *tag, const uint8_t *iv)
{
    const EVP_CIPHER *cipher = crypto->cipher;
    EVP_CIPHER_CTX *ctx = crypto->ctx2;

    int len;
    int plaintext_len;

    if (EVP_DecryptInit_ex(ctx, cipher, NULL, crypto->key, iv) != 1) {
        errx(1, "EVP_DecryptInit_ex failed");
    }
    if (EVP_CIPHER_CTX_ctrl (ctx, EVP_CTRL_GCM_SET_TAG, CRYPTO_TAG_SIZE, (uint8_t *) tag) != 1) {
        errx(1, "EVP_CIPHER_CTX_ctrl failed");
    }

    if (EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len) != 1) {
        errx(1, "EVP_DecryptUpdate failed");
    }

    plaintext_len = len;

    int r = EVP_DecryptFinal_ex(ctx, plaintext + len, &len);
    if (r != 1) {
        errx(1, "EVP_DecryptFinal_ex failed, r=%d", r);
    }
    plaintext_len += len;

    EVP_CIPHER_CTX_reset(ctx);

    return plaintext_len;
}
