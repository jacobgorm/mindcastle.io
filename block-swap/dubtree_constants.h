#ifndef __DUBTREE_CONSTANTS_H__
#define __DUBTREE_CONSTANTS_H__

#define DUBTREE_M 16ULL /* Level with multiplication factor. */
#define DUBTREE_MAX_LEVELS 16 /* Max depth of tree. We will never hit this. */
#define DUBTREE_SLOT_SIZE (16ULL<<20ULL) /* Smallest slot size. */
#define DUBTREE_BLOCK_SIZE 4096ULL /* Disk sector size. */

#define SIMPLETREE_NODESIZE 0x8000 /* Same as Windows' paging unit. */
#define SIMPLETREE_INNER_M 1258 /* Inner node width, squeezed just below 32kB. */
#define SIMPLETREE_LEAF_M 1090 /* Leaf node width, squeezed just below 32kB. */

#define CRYPTO_IV_SIZE (96 / 8)
#define CRYPTO_KEY_SIZE (256 / 8)
#define CRYPTO_TAG_SIZE (128 / 8)

typedef union {
    uint64_t first64;
    uint8_t bytes[128 / 8];
}__attribute__((__packed__)) hash_t;

#endif /* __DUBTREE_CONSTANTS_H__ */
