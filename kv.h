#ifndef __KV_H__
#define __KV_H__

#include <stdint.h>

struct DubTree;

#define KV_MAX_KEYS 0x1000

struct kv {
    struct DubTree *t;
    const char *kvdata;
    int fds[2];
    uint8_t *crypto_key;
    uint8_t *b;
    uint8_t *buffer;
    uint64_t base;
    uint64_t last_found;
    int last_offset;
    uint64_t keys[KV_MAX_KEYS];
    uint32_t sizes[KV_MAX_KEYS];
    uint32_t offsets[KV_MAX_KEYS];
    int n;
    int saved;
    void *find_context;
};

int kv_global_init(void);
int kv_init(struct kv *kv, const char *fn);
int kv_insert(struct kv *kv, uint64_t key, const uint8_t *value, size_t size);
int kv_find(struct kv *kv, uint8_t **rptr, size_t *rsize, uint64_t key);
int kv_flush(struct kv *kv);
int kv_save(struct kv *kv, char *buffer, size_t size);
int kv_close(struct kv *kv);

#endif /* __KV_H__ */
