#include "simpletree.h"

#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/rand.h>

#include "dubtree_io.h"
#include "crypto.h"

/* B-tree node ids can max be 16 bits. */
#if DUBTREE_TREENODES > (1<<16)
#error "number of tree nodes too large for 16 bits"
#endif
static inline node_t alloc_node(SimpleTree *st)
{
    SimpleTreeMetaNode *meta = get_meta(st);

    int r;
    int n = st->mem ? meta->num_nodes : 0;

    if (!((n - 1) & n)) {
        st->mem = realloc(st->mem, simpletree_node_size() * (n ? 2 * n : 1));
        put_node(st, 0);
        meta = get_meta(st);
        meta->num_nodes = n;
    }

    r = meta->num_nodes++;
    put_node(st, 0);
    return r;
}

static inline
void set_node_type(SimpleTree *st, node_t n,
        SimpleTreeNodeType type)
{
    SimpleTreeNode *nn = get_node(st, n);
    nn->type = type;
    /* Zero rest of node after header. XXX revisit later. */
    memset(&nn[1], 0, simpletree_node_size() - sizeof(*nn));
    put_node(st, n);
}

static void init_tree(SimpleTree *st, Crypto *crypto)
{
    memset(st->nodes, 0, sizeof(*st));
    st->crypto = crypto;
    st->fd = -1;
    st->node_buf = malloc(SIMPLETREE_NODESIZE);
}

void simpletree_create(SimpleTree *st, Crypto *crypto)
{
    assert(st);
    init_tree(st, crypto);

    alloc_node(st);
    set_node_type(st, 0, SimpleTreeNode_Meta);

    SimpleTreeMetaNode *meta = get_meta(st);
    meta->maxLevel = 0;
    meta->first = 0;
    meta->magic = 0xfedeabe0;
    put_node(st, 0);
}

void simpletree_close(SimpleTree *st)
{
    free(st->mem);
    free(st->user_data);
    free(st->node_buf);
    free(st->cached_nodes);
    if (st->is_encrypted) {
        lru_cache_close(&st->lru);
        hashtable_clear(&st->ht);
    }
    if (st->fd >= 0) {
        close(st->fd);
    }
}

void simpletree_open(SimpleTree *st, Crypto *crypto, int fd, hash_t hash)
{
    assert(hash.first64);
    SimpleTreeMetaNode *meta;
    init_tree(st, crypto);
    st->hash = hash;
    st->mem = NULL;
    st->fd = fd;
    st->is_encrypted = 1;
    const int log_lines = 6;
    lru_cache_init(&st->lru, log_lines);
    hashtable_init(&st->ht, NULL, NULL);
    st->cached_nodes = malloc(SIMPLETREE_NODESIZE * (1 << log_lines));

    assert(st->hash.first64);
    meta = get_meta(st);

    if (meta->magic!=0xfedeabe0){
        printf("bad magic %x!\n",meta->magic);
    }

    st->user_data = malloc(meta->user_size);
    if (meta->user_size <= (SIMPLETREE_NODESIZE - (CRYPTO_IV_SIZE + sizeof(*meta)))) {
        memcpy(st->user_data, (uint8_t *) meta + sizeof(*meta), meta->user_size);
    } else {
        node_t n = meta->num_nodes - (meta->user_size + SIMPLETREE_NODESIZE -
                1) / SIMPLETREE_NODESIZE;
        int take;
        int left;
        uint8_t *out = st->user_data;
        hash_t user_hash = meta->first_user_hash;
        for (left = meta->user_size; left > 0; left -= take, ++n, out += take) {
            const SimpleTreeUserNode *un = &get_node_hash(st, n, user_hash)->u.un;
            user_hash = un->next_hash;
            take = left < sizeof(un->data) ? left : sizeof(un->data);
            memcpy(out, un->data, take);
            put_node(st, n);
        }
    }
    assert(meta->magic == 0xfedeabe0);
    put_node(st, 0);
}

static void decrypt_node(SimpleTree *st, uint8_t *dst, const uint8_t *src, hash_t hash)
{
    //printf("decrypting with hash %016lx\n", hash.first64);
    assert(hash.first64);
    int r = decrypt256(st->crypto, dst, src + CRYPTO_IV_SIZE, SIMPLETREE_NODESIZE -
            CRYPTO_IV_SIZE, hash.bytes, src);
    if (r <= 0) {
        errx(1, "failed decrypting node");
    }
}

static int buffer_node(SimpleTree *st, node_t n)
{
    int left = SIMPLETREE_NODESIZE;
    int offset = 0;
    while (left) {
        ssize_t r;
        do {
            r = pread(st->fd, st->node_buf + offset, left,
                    SIMPLETREE_NODESIZE * n + offset);
        } while (r < 0 && errno == EINTR);
        if (r < 0) {
            err(1, "unable to read node %u", n);
        }
        left -= r;
        offset += r;
    }
    return 0;
}

void *simpletree_get_node(SimpleTree *st, node_t n, hash_t hash)
{
    uint64_t line;
    LruCacheLine *cl;
    void *ptr;

    if (hashtable_find(&st->ht, n, &line)) {
        cl = lru_cache_touch_line(&st->lru, line);
        ++(cl->users);
        ptr = (void *) cl->value;
    } else {
       for (;;) {
            line = lru_cache_evict_line(&st->lru);
            cl = lru_cache_touch_line(&st->lru, line);
            if (cl->users == 0) {
                break;
            }
        }
        if (cl->value) {
            hashtable_delete(&st->ht, cl->key);
        }
        ptr = st->cached_nodes + SIMPLETREE_NODESIZE * line;
        buffer_node(st, n);
        decrypt_node(st, ptr, st->node_buf, hash);
        cl->key = n;
        cl->value = (uintptr_t) ptr;
        cl->users = 1;
        hashtable_insert(&st->ht, n, line);
    }
    return ptr;
}

void simpletree_put_node(SimpleTree *st, node_t n)
{
    assert(st->is_encrypted);
    uint64_t line;
    LruCacheLine *cl;
    if (hashtable_find(&st->ht, n, &line)) {
        cl = lru_cache_get_line(&st->lru, line);
        --(cl->users);
    } else {
        assert(0);
    }
}

/* Factory functions for the inner and leaf node types. */

static inline node_t create_inner_node(SimpleTree *st)
{
    SimpleTreeInnerNode *in;
    node_t n = alloc_node(st);
    set_node_type(st, n, SimpleTreeNode_Inner);
    in = &get_node(st, n)->u.in;
    memset(in->children, 0, sizeof(in->children));
    in->count = 0;
    put_node(st, n);
    return n;
}

static inline node_t create_leaf_node(SimpleTree *st)
{
    SimpleTreeLeafNode *ln;
    node_t n = alloc_node(st);
    set_node_type(st, n, SimpleTreeNode_Leaf);
    ln = &get_node(st, n)->u.ln;
    ln->count = 0;
    ln->next = 0;
    put_node(st, n);
    return n;
}

static inline node_t create_user_node(SimpleTree *st)
{
    node_t n = alloc_node(st);
    set_node_type(st, n, SimpleTreeNode_User);
    put_node(st, n);
    return n;
}

/* Internal function to insert a key into an inner node. */

static inline void
simpletree_insert_inner(SimpleTree *st, int level, SimpleTreeInternalKey key)
{
    SimpleTreeInnerNode *in;

    /* If no node at this level create one. */
    if (st->nodes[level] == 0) {

        st->nodes[level] = create_inner_node(st);

        /* Did the tree just grow taller? */
        SimpleTreeMetaNode *meta = get_meta(st);
        if (level > meta->maxLevel) {
            meta->maxLevel = level;
        }
        put_node(st, 0);
    }

    node_t n = st->nodes[level];
    in = &get_node(st, n)->u.in;
    in->keys[in->count] = key;
    in->children[in->count] = st->nodes[level - 1];
    ++(in->count);

    if (in->count == SIMPLETREE_INNER_M) {
        simpletree_insert_inner(st, level + 1, key);
        st->nodes[level] = 0;
    }
    put_node(st, n);
}

/* Internal function to insert a key into a leaf node, possibly triggering the
 * recursive creation of one or more inner nodes as well. */

static inline void
simpletree_insert_leaf(SimpleTree *st, SimpleTreeInternalKey key, SimpleTreeValue value)
{
    /* If no node at this level create one. */

    if (st->nodes[0] == 0) {
        st->nodes[0] = create_leaf_node(st);
        if (st->prev) {
            SimpleTreeLeafNode *p = &get_node(st, st->prev)->u.ln;
            p->next = st->nodes[0];
            put_node(st, st->prev);
        } else {
            SimpleTreeMetaNode *meta = get_meta(st);
            meta->first = st->nodes[0];
            put_node(st, 0);
        }
    }

    node_t n = st->nodes[0];
    SimpleTreeLeafNode *ln = &get_node(st, n)->u.ln;
    assert(ln);
    ln->keys[ln->count] = key;
    ln->values[ln->count] = value;
    ++(ln->count);

    if (ln->count == SIMPLETREE_LEAF_M) {
        simpletree_insert_inner(st, 1, key);
        st->prev = st->nodes[0];
        st->nodes[0] = 0;
    }
    put_node(st, n);

}

/* Insert key as part of ordered sequence of inserts, into a tree created with
 * simpletree_create(). Call simpletree_finish() when done with all inserts. */

void simpletree_insert(SimpleTree *st, uint64_t key, SimpleTreeValue v)
{
    SimpleTreeInternalKey k;
    k.key = key;
    simpletree_insert_leaf(st, k, v);
}

/* Tie up any dangling tree references to finalize batch insertion.  When
 * inserting, we may have been working on e.g. a leaf node, that is is not
 * entirely full. Since we only connect a child with its parent when the child
 * fills up, we sometimes need to do this afterwards. The leaf may not have a
 * direct parent, so we will just connect it with the nearest ancestor.  This
 * means that we sometimes violate the normal B-tree invariant that all leaves
 * are at the bottommost level, which is generally fine given that we don't
 * need to modify the tree after creation. However, it means we cannot infer
 * from the current depth whether a node is a leaf or an inner node, but need
 * to check the node type to avoid embarrassing ourselves during lookups.  */
void simpletree_finish(SimpleTree *st)
{
    int i;
    SimpleTreeMetaNode *meta = get_meta(st);
    assert(meta->magic == 0xfedeabe0);

    for (i = 0 ; i < meta->maxLevel; ++i) {

        if (st->nodes[i] != 0) {

            int j;
            for (j = i + 1; j <= meta->maxLevel; ++j) {
                node_t parent = st->nodes[j];
                if (parent != 0) {
                    SimpleTreeInnerNode *in = &get_node(st, parent)->u.in;
                    in->children[in->count] = st->nodes[i];
                    put_node(st, parent);
                    break;
                }
            }
        }
    }
    meta->root = st->nodes[meta->maxLevel];
    put_node(st, 0);
}

static hash_t encrypt_node(SimpleTree *st, node_t n, hash_t next_hash)
{
    SimpleTreeNode *sn = get_node(st, n);
    SimpleTreeNodeType type = sn->type;
    if (type == SimpleTreeNode_Meta) {
        SimpleTreeMetaNode *meta = get_meta(st);
        hash_t nil = {};
        meta->root_hash = encrypt_node(st, meta->root, nil);
        meta->first_child_hash = st->first_child_hash;
        if (meta->user_size > (SIMPLETREE_NODESIZE - sizeof(*meta))) {
            node_t first = meta->num_nodes - (meta->user_size + SIMPLETREE_NODESIZE -
                    1) / SIMPLETREE_NODESIZE;
            node_t n = meta->num_nodes - 1;
            hash_t user_hash = {};
            for (; n >= first; --n) {
                user_hash = encrypt_node(st, n, user_hash);
            }
            meta->first_user_hash = user_hash;
        }
    } else if (type == SimpleTreeNode_Inner) {
        SimpleTreeInnerNode *in = &sn->u.in;
        hash_t neighbor_hash = st->tmp_hash;
        for (int i = in->count; i >= 0; --i) {
            if (in->children[i]) {
                neighbor_hash = in->child_hashes[i] =
                    encrypt_node(st, in->children[i], neighbor_hash);
            }
        }
    } else if (type == SimpleTreeNode_Leaf) {
        SimpleTreeLeafNode *ln = &sn->u.ln;
        ln->next_hash = next_hash;
    } else if (type == SimpleTreeNode_User) {
        SimpleTreeUserNode *un = &sn->u.un;
        un->next_hash = next_hash;
    }

    hash_t hash;
    uint8_t *tmp = st->node_buf;
    RAND_bytes(tmp, CRYPTO_IV_SIZE);
    encrypt256(st->crypto, tmp + CRYPTO_IV_SIZE, hash.bytes,
            (uint8_t *) sn, SIMPLETREE_NODESIZE - CRYPTO_IV_SIZE, tmp);
    memcpy(sn, tmp, SIMPLETREE_NODESIZE);

    if (type == SimpleTreeNode_Leaf) {
        st->first_child_hash = hash;
        st->tmp_hash = hash;
    }

    put_node(st, n);
    return hash;
}

hash_t simpletree_encrypt(SimpleTree *st)
{
    hash_t nil = {};
    st->hash = encrypt_node(st, 0, nil);
    assert(st->hash.first64);
    return st->hash;
}

static inline int less_than(
        const SimpleTree *st,
        const SimpleTreeInternalKey *a, const SimpleTreeInternalKey *b)
{
    return (a->key < b->key);
}

static inline int lower_bound(const SimpleTree *st,
        const SimpleTreeInternalKey *first, size_t len, const SimpleTreeInternalKey *key)
{
    int half;
    const SimpleTreeInternalKey *middle;
    const SimpleTreeInternalKey *f = first;
    while (len > 0) {
        half = len >> 1;
        middle = f + half;
        if (less_than(st, middle, key)) {
            f = middle + 1;
            len = len - half - 1;
        } else
            len = half;
    }
    return f - first;
}

/* Recurse through the B-tree looking for a key. As explained in the comment
 * for simpletree_finish(), the tree is not always entirely well-formed, so we
 * need to check for nil-references, and we need to check the type of a given
 * node to figure out if is an inner node or leaf, instead of just relying on
 * the current depth as would be possible with a well-formed B-tree. */
int simpletree_find(SimpleTree *st, uint64_t key, SimpleTreeIterator *it)
{
    SimpleTreeMetaNode *meta = get_meta(st);
    const SimpleTreeInternalKey needle = {key};
    node_t n = meta->root;
    int r = 0;
    hash_t hash = meta->root_hash;

    while (n) {

        int pos;
        node_t next;
        SimpleTreeNode *sn = get_node_hash(st, n, hash);
        int type = sn->type;

        if (type == SimpleTreeNode_Inner) {

            SimpleTreeInnerNode *in = &sn->u.in;
            pos = lower_bound(st, in->keys, in->count, &needle);
            next = in->children[pos];
            hash = in->child_hashes[pos];

        } else {

            SimpleTreeLeafNode *ln = &sn->u.ln;
            pos = lower_bound(st, ln->keys, ln->count, &needle);
            assert(pos < SIMPLETREE_LEAF_M);

            if (pos < ln->count) {
                it->node = n;
                it->hash = hash;
                it->index = pos;
                r = 1;
            } else {
                it->node = 0;
                it->index = 0;
                hash_t nil = {};
                it->hash = nil;
            }

            next = 0;
        }

        put_node(st, n);
        n = next;
    }
    put_node(st, 0);
    return r;
}

void simpletree_set_user(SimpleTree *st, const void *data, size_t size)
{
    SimpleTreeMetaNode *meta = get_meta(st);
    meta->user_size = size;
    if (size <= (SIMPLETREE_NODESIZE - (CRYPTO_IV_SIZE + sizeof(*meta)))) {
        memcpy((uint8_t *) meta + sizeof(*meta), data, size);
    } else {
        size_t take;
        size_t left;
        const uint8_t *in = data;
        for (left = size; left > 0; in += take, left -= take) {
            node_t n = create_user_node(st);
            SimpleTreeUserNode *un = &get_node(st, n)->u.un;
            take = left < sizeof(un->data) ? left : sizeof(un->data);
            memcpy(un->data, in, take);
            put_node(st, n);
        }
    }
    put_node(st, 0);
}

const void *simpletree_get_user(SimpleTree *st)
{
    return st->user_data;
}
