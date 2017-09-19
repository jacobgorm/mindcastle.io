#ifndef __HEX_H__
#define __HEX_H__

#include <stdint.h>

#if 0
static inline int unhex(uint8_t* out,char*in)
{
    int i;
    int shift=4;
    int digit = 0;

    for(i=0; i < 40; i++) {
        char c = *in++;
        if(c>='0' && c<='9') c-='0';
        else if(c>='a' && c<='f') c-= ('a'-0xa);
        else if(c>='A' && c<='F') c-= ('A'-0xa);
        else return -1;

        digit |= c << shift;
        shift ^= 4;

        if(shift) {
            *out++ = digit;
            digit=0;
        }
    }
    return 0;
}
#endif

static inline void hex(char* out, const uint8_t* in, size_t sz)
{
//    assert(sz==64);
    int i;
    char* o = out;
    char digits[] = "0123456789abcdef";
    for(i=0; i < sz; i++)
    {
        char c = *in++;
        *o++= digits[(c & 0xf0)>>4];
        *o++= digits[ c & 0xf];
    }
    *o = '\0';
}

#endif /* __HEX_H__ */
