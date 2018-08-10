/* Copyright (c) 2012-2016 Bromium Inc.
 * All rights reserved
 * Author: Jacob Gorm Hansen
 *
 * Sanity-check contents of .swap disk.
*/

#include <assert.h>
#include <err.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "block.h"
#include "block-swap.h"
#include "aio.h"
#include "ioh.h"

int main(int argc, char **argv)
{
#ifdef _WIN32
    setprogname(argv[0]);
#endif

    BlockDriverState bs;
    //int r;

    if (argc != 2) {
        fprintf(stderr, "usage: %s <dst.swap>\n",
                argv[0]);
        exit(-1);
    }

    ioh_init();
    swap_aio_init();

    const char *dst = argv[1];
    int r;

    r = swap_open(&bs, dst, 0);
    if (r < 0) {
        fprintf(stderr, "%s: unable to open %s\n", argv[0], dst);
    }
    r = swap_ioctl(&bs, 2, NULL);
    if (r < 0) {
        fprintf(stderr, "%s: unable to fsck %s\n", argv[0], dst);
    }

    if (r == 0) {
        fprintf(stderr, "fsck completed.\n");
    }
    swap_close(&bs);
    return r;
}
