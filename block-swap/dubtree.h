#ifndef __DUBTREE_H__
#define __DUBTREE_H__

#if defined (QEMU_UXEN) || defined(LIBIMG)
#include <dm/config.h>
#else
#include "config.h"
#endif

#include "dubtree_constants.h"
#include "crypto.h"
#include "hashtable.h"
#include "lrucache.h"

#define DUBTREE_MAX_FALLBACKS 8
#define DUBTREE_HASH_SIZE (512/8)

/* The per-instance in-memory representation of a dubtree. */

typedef struct {
    union {
        uint64_t first64;
        uint8_t bytes[256 / 8];
    } id;
    uint32_t size;
} chunk_id_t;

static inline void clear_chunk_id(chunk_id_t *chunk_id)
{
    memset(chunk_id, 0, sizeof(*chunk_id));
}

static inline int valid_chunk_id(const chunk_id_t *chunk_id)
{
    return chunk_id->size != 0;
}

static inline int equal_chunk_ids(const chunk_id_t *a, const chunk_id_t *b)
{
    //assert(valid_chunk_id(a));
//    assert(valid_chunk_id(b));
    return (a->size == b->size &&
            !memcmp(a->id.bytes, b->id.bytes, sizeof(a->id.bytes)));
}

typedef void (*read_callback) (void *opaque, int result);
typedef int (*commit_callback) (void *opaque);

struct CacheLineUserData;

struct level_ptr {
    int level;
    chunk_id_t level_id;
    hash_t level_hash;
};

typedef struct DubTree {
    critical_section write_lock;

    struct level_ptr first;

    int use_large_values;
    const uint8_t *crypto_key;
    char *fallbacks[DUBTREE_MAX_FALLBACKS + 1];
    char *cache;
    critical_section cache_lock;
    HashTable ht;
    LruCache lru;
    struct CacheLineUserData *cache_infos;
    HashTable refcounts_ht;
    int buffer_max;
    void *buffered;
    void *head_ch, *shared_ch;

} DubTree;

int dubtree_insert(DubTree *t, int num_keys, uint64_t* keys,
        uint8_t *values, uint32_t *sizes,
        int force_level, commit_callback commit_cb, void *opaque);

void *dubtree_prepare_find(DubTree *t);
void dubtree_end_find(DubTree *t, void *ctx);

int dubtree_find(DubTree *t, uint64_t start, int num_keys,
        uint8_t *out, size_t *buffer_size,
        uint8_t *map, uint32_t *sizes,
        read_callback cb, void *opaque, void *ctx);

int dubtree_init(DubTree *t, const uint8_t *key,
        chunk_id_t top_id, hash_t top_hash,
        char **fallbacks, char *cache,
        int use_large_values);
int dubtree_checkpoint(DubTree *t, chunk_id_t *top_id, hash_t *top_hash);
int dubtree_snapshot(DubTree *t, const char *name);
void dubtree_close(DubTree *t);
int dubtree_delete(DubTree *t);
void dubtree_quiesce(DubTree *t);
int dubtree_sanity_check(DubTree *t);

#endif /* __DUBTREE_H__ */
