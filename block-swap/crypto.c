#include <assert.h>
#include <openssl/aes.h>
#include <openssl/sha.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <string.h>
#include <err.h>

#include "crypto.h"

void strong_hash(uint8_t *hash, const uint8_t *in, int size)
{
    SHA512(in, size, hash);
}

static EVP_CIPHER_CTX *ctx1 = NULL;
static EVP_CIPHER_CTX *ctx2 = NULL;
static const EVP_CIPHER *cipher = NULL;

int crypto_init(void)
{
    if (!(ctx1 = EVP_CIPHER_CTX_new())) {
        errx(1, "EVP_CIPHER_CTX_new failed");
    }
    if (!(ctx2 = EVP_CIPHER_CTX_new())) {
        errx(1, "EVP_CIPHER_CTX_new failed");
    }
    cipher = EVP_aes_128_gcm();
    if (!cipher) {
        errx(1, "EVP_aes_128_gcm failed");
    }
    if (RAND_load_file("/dev/random", 32) != 32) {
        errx(1, "RAND_load_file failed");
    }
    return 0;
}

int encrypt128(uint8_t *ciphertext, uint8_t *tag, const uint8_t *plaintext, int plaintext_len,
        const uint8_t *key, const uint8_t *iv)
{

    assert(ctx1);
    assert(cipher);

    int len;
    int ciphertext_len = 0;

    if (EVP_EncryptInit_ex(ctx1, cipher, NULL, key, iv) != 1) {
        errx(1, "EVP_EncryptInit_ex failed");
    }

    if (EVP_EncryptUpdate(ctx1, ciphertext + ciphertext_len, &len, plaintext, plaintext_len) != 1) {
        errx(1, "EVP_EncryptUpdate failed");
    }
    ciphertext_len += len;

    if (EVP_EncryptFinal_ex(ctx1, ciphertext + ciphertext_len, &len) != 1) {
        errx(1, "EVP_EncryptFinal_ex failed");
    }
    ciphertext_len += len;
    
    if (EVP_CIPHER_CTX_ctrl(ctx1, EVP_CTRL_GCM_GET_TAG, CRYPTO_TAG_SIZE, tag) != 1) {
        errx(1, "EVP_EncryptFinal_ex failed");
    }

    /* Clean up */
    EVP_CIPHER_CTX_reset(ctx1);

    return ciphertext_len;
}

int decrypt128(uint8_t *plaintext, const uint8_t *ciphertext, int ciphertext_len,
        const uint8_t *tag, const uint8_t *key, const uint8_t *iv)
{
    int len;
    int plaintext_len;

    if (EVP_DecryptInit_ex(ctx2, cipher, NULL, key, iv) != 1) {
        errx(1, "EVP_DecryptInit_ex failed");
    }
    if (EVP_CIPHER_CTX_ctrl (ctx2, EVP_CTRL_GCM_SET_TAG, CRYPTO_TAG_SIZE, (uint8_t *) tag) != 1) {
        errx(1, "EVP_CIPHER_CTX_ctrl failed");
    }

    if (EVP_DecryptUpdate(ctx2, plaintext, &len, ciphertext, ciphertext_len) != 1) {
        errx(1, "EVP_DecryptUpdate failed");
    }

    plaintext_len = len;

    int r = EVP_DecryptFinal_ex(ctx2, plaintext + len, &len);
    if (r != 1) {
        errx(1, "EVP_DecryptFinal_ex failed, r=%d", r);
    }
    plaintext_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_reset(ctx2);

    return plaintext_len;
}
