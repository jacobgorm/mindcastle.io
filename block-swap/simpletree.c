#include "simpletree.h"

#include <limits.h>
#include <stdlib.h>
#include <string.h>

#include "dubtree_io.h"

/* B-tree node ids can max be 16 bits. */
#if DUBTREE_TREENODES > (1<<16)
#error "number of tree nodes too large for 16 bits"
#endif

static inline node_t alloc_node(SimpleTree *st)
{
    SimpleTreeMetaNode *meta = &get_node(st, 0)->u.mn;

    int r;
    int n = st->mem ? meta->num_nodes : 0;

    if (!((n - 1) & n)) {
        st->mem = realloc(st->mem, simpletree_node_size() * (n ? 2 * n : 1));
        put_node(st, 0);
        meta = &get_node(st, 0)->u.mn;
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
    __sync_synchronize();
}

void simpletree_create(SimpleTree *st)
{
    assert(st);
    st->mem = NULL;
    st->user_data = NULL;
    st->prev = 0;
    st->refs = 0;
    st->users = 0;

    memset(st->nodes, 0, sizeof(st->nodes));

    alloc_node(st);
    set_node_type(st, 0, SimpleTreeNode_Meta);

    SimpleTreeMetaNode *meta = &get_node(st, 0)->u.mn;
    meta->maxLevel = 0;
    meta->first = 0;
    meta->magic = 0xfedeabe0;
    put_node(st, 0);
    __sync_synchronize();
}

void simpletree_close(SimpleTree *st)
{
    free(st->mem);
    free(st->user_data);
}

/* Create a new SimpleTree instance wrapping the tree with meta node mn, in the
 * node space mem, with freelist starting at head. Assumes that mn already has
 * a non-zero refcount. Returns NULL if no tree at this level. XXX will assert
 * on malloc failure, we should change this to have the caller do the malloc,
 * but this will be wasteful for the common case of having no tree. */
void simpletree_open(SimpleTree *st, void *mem)
{
    SimpleTreeMetaNode *meta;
    assert(st);
    memset(st, 0, sizeof(*st));
    st->mem = mem;

    meta = &get_node(st, 0)->u.mn;

    if (meta->magic!=0xfedeabe0){
        printf("bad magic %x!\n",meta->magic);
    }

    st->user_data = malloc(meta->user_size);
    memcpy(st->user_data, (uint8_t *) meta + sizeof(*meta), meta->user_size);

    assert(meta->magic == 0xfedeabe0);
    put_node(st, 0);
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

/* Internal function to insert a key into an inner node. */

static inline void
simpletree_insert_inner(SimpleTree *st, int level, SimpleTreeInternalKey key)
{
    SimpleTreeInnerNode *in;

    /* If no node at this level create one. */
    if (st->nodes[level] == 0) {

        st->nodes[level] = create_inner_node(st);

        /* Did the tree just grow taller? */
        SimpleTreeMetaNode *meta = &get_node(st, 0)->u.mn;
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
            SimpleTreeMetaNode *meta = &get_node(st, 0)->u.mn;
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
    SimpleTreeMetaNode *meta = &get_node(st, 0)->u.mn;
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
    int init = st->refs;
    SimpleTreeMetaNode *meta = &get_node(st, 0)->u.mn;
    const SimpleTreeInternalKey needle = {key};
    node_t n = meta->root;
    int r = 0;

    while (n) {

        int pos;
        node_t next;

        SimpleTreeNode *sn = get_node(st, n);
        int type = sn->type;

        if (type == SimpleTreeNode_Inner) {

            SimpleTreeInnerNode *in = &sn->u.in;
            pos = lower_bound(st, in->keys, in->count, &needle);
            next = in->children[pos];

        } else {

            SimpleTreeLeafNode *ln = &sn->u.ln;
            pos = lower_bound(st, ln->keys, ln->count, &needle);
            assert(pos < SIMPLETREE_LEAF_M);

            if (pos < ln->count) {
                it->node = n;
                it->index = pos;
                r = 1;
            } else {
                it->node = 0;
                it->index = 0;
            }

            next = 0;
        }

        put_node(st, n);
        n = next;
    }
    put_node(st, 0);
    assert(st->refs == init);
    return r;
}

void simpletree_set_user(SimpleTree *st, const void *data, size_t size)
{
    SimpleTreeMetaNode *meta = &get_node(st, 0)->u.mn;
    meta->user_size = size;

    if (size <= (SIMPLETREE_NODESIZE - sizeof(*meta))) {
        memcpy((uint8_t *) meta + sizeof(*meta), data, size);
    } else {
        assert(0);
        int take;
        int left;
        const uint8_t *in = data;
        uint8_t *out;
        for (left = size; left > 0; in += take, left -= take) {
            take = left < SIMPLETREE_NODESIZE ? left : SIMPLETREE_NODESIZE;
            node_t n = alloc_node(st);
            out = (uint8_t *) get_node(st, n);
            memcpy(out, in, take);
            memset(out + take, 0, SIMPLETREE_NODESIZE - take);
            put_node(st, n);
        }
    }
    put_node(st, 0);
}

const void *simpletree_get_user(SimpleTree *st)
{
    return st->user_data;
}
