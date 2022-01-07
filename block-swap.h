#ifndef __BLOCK_SWAP_H__
#define __BLOCK_SWAP_H__

#include "tinyuuid.h"

typedef struct BlockDriverState {
    void *opaque;
    uint64_t total_sectors;
} BlockDriverState;

typedef void BlockDriverCompletionFunc(void *opaque, int ret);

typedef struct BlockDriverAIOCB {
    BlockDriverCompletionFunc *cb;
    void *opaque;
} BlockDriverAIOCB;


BlockDriverAIOCB *swap_aio_write(BlockDriverState *bs, int64_t sector_num,
        const uint8_t *buf, int nb_sectors,
        BlockDriverCompletionFunc *cb, void *opaque);

BlockDriverAIOCB *swap_aio_read(BlockDriverState *bs,
        int64_t sector_num, uint8_t *buf, int nb_sectors,
        BlockDriverCompletionFunc *cb, void *opaque);

struct ioh_event;
int swap_flush(BlockDriverState *bs, BlockDriverCompletionFunc *cb,
        void *opaque);
void swap_close(BlockDriverState *bs);
int swap_create(const char *filename, int64_t size, int flags);
int swap_open(BlockDriverState *bs, const char *filename, int flags);
int swap_remove(BlockDriverState *bs);
int swap_ioctl(BlockDriverState *bs, unsigned long int req, void *buf);
int swap_snapshot(BlockDriverState *bs, uuid_t uuid);
int swap_getsize(BlockDriverState *bs, uint64_t *result);

#endif /* __BLOCK_SWAP_H__ */
