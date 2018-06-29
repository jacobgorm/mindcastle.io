#ifndef __SIMPLETREE_H__
#define __SIMPLETREE_H__

#include "dubtree_sys.h"
#include "dubtree_constants.h"
#include "crypto.h"
#include "hashtable.h"
#include "lrucache.h"
#include "crypto.h"

typedef uint32_t node_t;

typedef struct SimpleTreeMetaNode {
    node_t root;        /* root node offset */
    node_t first;       /* leftmost leaf node offset */
    hash_t first_hash;
    int maxLevel;       /* Height of tree */
    uint32_t magic;
    uint32_t num_nodes;
    uint32_t user_size;   /* Size of user-supplied data. */
    hash_t root_hash;
} SimpleTreeMetaNode;

/* Per-instance tree handle. Most values are only relevant
 * during tree construction. */

typedef struct SimpleTree {
    node_t nodes[16];
    node_t prev;
    int fd;
    uint8_t *mem;
    uint8_t *user_data;
    uint64_t size;
    hash_t hash;
    hash_t first_hash;
    hash_t tmp_hash;
    Crypto crypto;
    int is_encrypted;
    LruCache lru;
    HashTable ht;
    uint8_t *cached_nodes;

} SimpleTree;

typedef struct SimpleTreeInternalKey {
    uint64_t key : 48;
} __attribute__((__packed__)) SimpleTreeInternalKey;

typedef struct {
    uint32_t chunk : 24;
    uint32_t offset : 24;
    uint32_t size : 16;
    hash_t hash;
} __attribute__((__packed__)) SimpleTreeValue;

typedef struct SimpleTreeResult {
    uint64_t key;
    SimpleTreeValue value;
} SimpleTreeResult;

typedef struct SimpleTreeIterator {
    size_t index;
    node_t node;
    hash_t hash;
} SimpleTreeIterator;

typedef struct SimpleTreeInnerNode {
    int count;
    SimpleTreeInternalKey keys[SIMPLETREE_INNER_M];
    node_t children[SIMPLETREE_INNER_M + 1];
    hash_t child_hashes[SIMPLETREE_INNER_M + 1];
} SimpleTreeInnerNode ;

typedef struct SimpleTreeLeafNode {
    int count;
    node_t next;
    hash_t next_hash;
    SimpleTreeInternalKey keys[SIMPLETREE_LEAF_M];
    SimpleTreeValue values[SIMPLETREE_LEAF_M];
} SimpleTreeLeafNode ;

typedef enum {
    SimpleTreeNode_Free = 0,
    SimpleTreeNode_Meta = 1,
    SimpleTreeNode_Inner = 2,
    SimpleTreeNode_Leaf = 3,
} SimpleTreeNodeType;

typedef struct SimpleTreeNode {
    uint32_t type;
    union {
        SimpleTreeMetaNode mn;
        SimpleTreeLeafNode ln;
        SimpleTreeInnerNode in;
    } u;
} SimpleTreeNode;

void simpletree_create(SimpleTree *st);
void *simpletree_get_node(SimpleTree *st, node_t n, hash_t hash);
void simpletree_put_node(SimpleTree *st, node_t n);

void simpletree_close(SimpleTree *st);
void simpletree_insert(SimpleTree *st, uint64_t key, SimpleTreeValue v);
void simpletree_finish(SimpleTree *st);
hash_t simpletree_encrypt(SimpleTree *st);
int simpletree_find(SimpleTree *st, uint64_t key, SimpleTreeIterator *it);

void simpletree_open(SimpleTree *st, void *mem, hash_t hash);
void simpletree_set_user(SimpleTree *st, const void *data, size_t size);
const void *simpletree_get_user(SimpleTree *st);

/* Free the per-process in-memory tree representation and
 * NULL the pointer to it to prevent future use. */

static inline size_t simpletree_node_size(void)
{
#if 0
    printf("szk %lx\n", sizeof(SimpleTreeInternalKey));
    printf("szv %lx\n", sizeof(SimpleTreeValue));
    printf("szm %lx\n", sizeof(SimpleTreeMetaNode));
    printf("szln %lx\n", sizeof(SimpleTreeLeafNode));
    printf("szin %lx\n", sizeof(SimpleTreeInnerNode));
    printf("sz %lx\n", sizeof(SimpleTreeNode));
    exit(0);
#endif
    assert(sizeof(hash_t) == 16);
    assert(sizeof(SimpleTreeNode) <= SIMPLETREE_NODESIZE - CRYPTO_IV_SIZE);
    return SIMPLETREE_NODESIZE;
}

static inline SimpleTreeNode* get_node_hash(SimpleTree *st, node_t n, hash_t hash)
{
    if (st->is_encrypted) {
        return simpletree_get_node(st, n, hash);
    } else {
        return (SimpleTreeNode*) ((uint8_t*) st->mem + simpletree_node_size() * n);
    }
}

static inline SimpleTreeNode* get_node(SimpleTree *st, node_t n)
{
    hash_t dummy = {};
    return get_node_hash(st, n, dummy);
}

static inline void put_node(SimpleTree *st, node_t n)
{
    if (st->is_encrypted) {
        simpletree_put_node(st, n);
    }
}

static inline SimpleTreeMetaNode *get_meta(SimpleTree *st)
{
    return &get_node_hash(st, 0, st->hash)->u.mn;
}

static inline size_t simpletree_get_nodes_size(SimpleTree *st)
{
    SimpleTreeMetaNode *meta = get_meta(st);
    size_t r = simpletree_node_size() * meta->num_nodes;
    put_node(st, 0);
    return r;
}

static inline void simpletree_begin(SimpleTree *st, SimpleTreeIterator *it)
{
    SimpleTreeMetaNode *meta = get_meta(st);
    it->node = meta->first;
    it->hash = meta->first_hash;
    assert(it->hash.first64);
    it->index = 0;
    put_node(st, 0);
}

static inline void simpletree_next(SimpleTree *st, SimpleTreeIterator *it)
{
    node_t n = it->node;
    assert(it->hash.first64);
    SimpleTreeLeafNode *ln = &get_node_hash(st, n, it->hash)->u.ln;
    if (++(it->index) == ln->count) {
        it->node = ln->next;
        it->hash = ln->next_hash;
        assert(it->node == 0 || it->hash.first64);
        it->index = 0;
    }
    put_node(st, n);
}

static inline int simpletree_at_end(SimpleTree *st, SimpleTreeIterator *it)
{
    return (it->node == 0);
}

static inline SimpleTreeResult simpletree_read(SimpleTree *st,
        SimpleTreeIterator *it)
{
    assert(st->mem);
    SimpleTreeResult r;
    node_t n = it->node;
    const SimpleTreeLeafNode *ln = &get_node_hash(st, n, it->hash)->u.ln;
    const SimpleTreeInternalKey *k = &ln->keys[it->index];

    r.key = k->key;
    r.value = ln->values[it->index];
    put_node(st, n);
    return r;
}

#endif /* __SIMPLETREE_H__ */
