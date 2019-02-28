#include <stdio.h>
#include <err.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>


#include "tinyuuid.h"

void tiny_uuid_generate_random(uuid_t out) {
    int r;
    int f = open("/dev/urandom", O_RDONLY);
    if (f >= 0) {
        do {
            r = read(f, out, sizeof(uuid_t));
        } while (r == EINTR);
        close(f);
    } else {
        err(1, "unable to open /dev/urandom");
    }

}

void tiny_uuid_unparse(uuid_t src, char *dst) {

    for (int i = 0; i < 16; ++i) {
        switch (i) {
            case 4:
            case 6:
            case 8:
            case 10:
                *dst++ = '-';
            default:
                break;
        }
        sprintf(dst, "%02x", src[i]);
        dst +=2 ;
    }
    *dst = '\0';
}

static inline unsigned int hex_to_int(char c) {
    char d = (c >= '0' && c <= '9') ? '0' :
        (c >= 'a' && c <= 'f') ? ('a' - 0xa) :
        (c >= 'A' && c <= 'F') ?  ('A' - 0xa) : 0;
    return c - d;
}

int tiny_uuid_parse(char *src, uuid_t dst) {

    for (int i = 0; i < 16; ++i) {
        switch (i) {
            case 4:
            case 6:
            case 8:
            case 10:
                if (*src++ != '-') {
                    return -1;
                }
            default:
                break;
        }
        *dst++ = (hex_to_int(src[0]) << 4) | hex_to_int(src[1]);
        src += 2;
    }
    return 0;
}
