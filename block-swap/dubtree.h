#ifndef __DUBTREE_H__
#define __DUBTREE_H__

#if defined (QEMU_UXEN) || defined(LIBIMG)
#include <dm/config.h>
#else
#include "config.h"
#endif

#include "dubtree_constants.h"
#include "cbf.h"
#include "crypto.h"
#include "hashtable.h"
#include "lrucache.h"

#define DUBTREE_MAX_FALLBACKS 8
#define DUBTREE_HASH_SIZE (512/8)

/* The per-instance in-memory representation of a dubtree. */

typedef struct {
    union {
        uint64_t first64;
        uint8_t bytes[512 / 8];
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

typedef struct DubTreeHeader {
    uint32_t magic, version;
    uint32_t dubtree_m;
    uint32_t dubtree_slot_size;
    uint32_t dubtree_max_levels;
    chunk_id_t levels[DUBTREE_MAX_LEVELS];
    hash_t hashes[DUBTREE_MAX_LEVELS];
} DubTreeHeader;

typedef void (*read_callback) (void *opaque, int result);
typedef void *(*malloc_callback) (void *opaque, size_t sz);
typedef void (*free_callback) (void *opaque, void *ptr);

struct CacheLineUserData;

typedef struct DubTree {
    critical_section write_lock;
    DubTreeHeader *header;
    /*volatile */ chunk_id_t *levels;
    /*volatile */ hash_t *hashes;

    const uint8_t *crypto_key;
    char *fallbacks[DUBTREE_MAX_FALLBACKS + 1];
    char *cache;
    critical_section cache_lock;
    HashTable ht;
    LruCache lru;
    struct CacheLineUserData *cache_infos;
    CBF cbf;
    int buffer_max;
    void *buffered;
    malloc_callback malloc_cb;
    free_callback free_cb;
    void *opaque;

} DubTree;

int dubtree_insert(DubTree *t, int numKeys, uint64_t* keys,
        uint8_t *values, uint32_t *sizes, int force_level);

void *dubtree_prepare_find(DubTree *t);
void dubtree_end_find(DubTree *t, void *ctx);

int dubtree_find(DubTree *t, uint64_t start, int num_keys,
        uint8_t *out, uint8_t *map, uint32_t *sizes,
        read_callback cb, void *opaque, void *ctx);

int dubtree_init(DubTree *t, const uint8_t *key, chunk_id_t top_id, char **fallbacks, char *cache,
        malloc_callback malloc_cb, free_callback free_cb, void *opaque);
chunk_id_t dubtree_checkpoint(DubTree *t);
void dubtree_close(DubTree *t);
int dubtree_delete(DubTree *t);
void dubtree_quiesce(DubTree *t);
int dubtree_sanity_check(DubTree *t);

#endif /* __DUBTREE_H__ */
