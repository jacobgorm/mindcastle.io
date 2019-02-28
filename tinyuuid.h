#ifndef __UUID_H__
#define __UUID_H__

typedef unsigned char uuid_t[16];
void tiny_uuid_generate_random(uuid_t out);
void tiny_uuid_unparse(uuid_t src, char *dst);
int tiny_uuid_parse(char *src, uuid_t dst);

#endif /* __UUID_H__ */
