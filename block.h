
#ifndef _BLOCK_H_
#define _BLOCK_H_

#include <stdbool.h>

typedef struct BlockDriverInfo {
    /* in bytes, 0 if irrelevant */
    int cluster_size;
    /* offset at which the VM state can be saved (0 if not possible) */
    int64_t vm_state_offset;
} BlockDriverInfo;

#define BDRV_SECTOR_BITS   9ULL
#define BDRV_SECTOR_SIZE   (1ULL << BDRV_SECTOR_BITS)
#define BDRV_SECTOR_MASK   ~(BDRV_SECTOR_SIZE - 1ULL)

#endif
