
#define _GNU_SOURCE

#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <linux/nbd.h>
#include <linux/types.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include "aio.h"
#include "ioh.h"
#include "block-swap.h"

struct sock_info {
    ioh_event event;
    int sock;
};

struct BlockDriverState;
struct client_info {
    ioh_event event;
    struct BlockDriverState *bs;
    int sock;
};

struct read_info {
    struct client_info *ci;
    uint8_t *buffer;
    int len;
    struct nbd_reply reply;
};

static void got_data(void *opaque);

static void nbd_read_done(void *opaque, int ret) {
    int r;
    struct read_info *ri = opaque;
    struct client_info *ci = ri->ci;

    r = write(ci->sock, &ri->reply, sizeof(ri->reply));
    assert(r == sizeof(ri->reply));

    r = write(ci->sock, ri->buffer, ri->len);
    assert(r == ri->len);

    free(ri->buffer);
    free(ri);

    aio_add_wait_object(&ci->event, got_data, ci);
}

static void nbd_write_done(void *opaque, int ret) {
    uint8_t *buffer = opaque;
    free(buffer);
}

static void got_data(void *opaque)
{
    struct client_info *ci = opaque;
    struct nbd_request request;
    struct nbd_reply reply = {};
    int r;

    r = read(ci->sock, &request, sizeof(request));
    if (r == sizeof(request)) {
        memcpy(reply.handle, request.handle, sizeof(reply.handle));
        reply.magic = htonl(NBD_REPLY_MAGIC);
        reply.error = htonl(0);
        assert(request.magic == htonl(NBD_REQUEST_MAGIC));
        int len = ntohl(request.len);
        switch(ntohl(request.type)) {
            case NBD_CMD_FLUSH: {
                printf("got flush\n");
                swap_flush(ci->bs);
                r = write(ci->sock, &reply, sizeof(reply));
                assert(r == sizeof(reply));
                break;
            }

            case NBD_CMD_DISC: {
                printf("got disc\n");
                swap_close(ci->bs);
                exit(0);
                break;
            }

            case NBD_CMD_READ: {
    //            r = write(ci->sock, &reply, sizeof(reply));
                int len = ntohl(request.len);
                //uint64_t offset =  ntohll(request.from);
                uint64_t offset =  be64toh(request.from);
                struct read_info *ri = malloc(sizeof(struct read_info));
                ri->ci = ci;
                ri->buffer = malloc(len);
                ri->len = len;
                ri->reply = reply;

                swap_aio_read(ci->bs, offset / 512, ri->buffer, len / 512, nbd_read_done, ri);
                break;
            }
            case NBD_CMD_WRITE: {
                assert(!(len % 4096));
                r = write(ci->sock, &reply, sizeof(reply));
                uint8_t *buffer = malloc(len);
                int len = ntohl(request.len);
                uint64_t offset = be64toh(request.from);
                uint8_t *b;
                int left;

                for (left = len, b = buffer; left > 0; b += r, left -= r)  {
                    r = read(ci->sock, b, left);
                    assert(r >= 0);
                }
                swap_aio_write(ci->bs, offset / 512, buffer, len / 512, nbd_write_done, buffer);
                aio_add_wait_object(&ci->event, got_data, ci);

                break;
            }

            default: {
                printf("default %x\n", ntohl(request.type));
                r = write(ci->sock, &reply, sizeof(reply));
                assert(r == sizeof(reply));
                aio_add_wait_object(&ci->event, got_data, ci);
                break;
            }
        };
    }
}

static BlockDriverState bs;

void signal_handler(int s)
{
    swap_flush(&bs);
    swap_close(&bs);
    exit(1);
}

int main(int argc, char **argv)
{
    int r;
    struct sigaction sig;
    sig.sa_handler = signal_handler;
    sigemptyset(&sig.sa_mask);
    sig.sa_flags = 0;
    sigaction(SIGINT, &sig, NULL);

    swap_create("foo.swap", 100 << 20, 0);
    swap_open(&bs, "foo.swap", 0);

    int sp[2];
    r = socketpair(AF_UNIX, SOCK_STREAM, 0, sp);
    assert(r == 0);

    int device = open("/dev/nbd0", O_RDWR);
    assert(device >= 0);

    r = ioctl(device, NBD_SET_SIZE_BLOCKS, 1000 << 20);
    assert(r == 0);

    r = ioctl(device, NBD_SET_BLKSIZE, 0x1000);
    assert(r == 0);

    r = ioctl(device, NBD_CLEAR_SOCK);
    assert(r == 0);

    if (!fork()) {
        close(sp[0]);
        if(ioctl(device, NBD_SET_SOCK, sp[1]) == -1){
            fprintf(stderr, "NBD_SET_SOCK failed %s\n", strerror(errno));
        }
        else {
            r = ioctl(device, NBD_DO_IT);
            fprintf(stderr, "nbd device terminated %d\n", r);
            if (r == -1)
                fprintf(stderr, "%s\n", strerror(errno));
        }
        ioctl(device, NBD_CLEAR_QUE);
        ioctl(device, NBD_CLEAR_SOCK);
        exit(0);
    }


    struct client_info *ci = malloc(sizeof(struct client_info));
    ci->sock = sp[0];
    ioh_event_init_fd(&ci->event, ci->sock);
    ci->bs = &bs;
    aio_add_wait_object(&ci->event, got_data, ci);


#if 0

    int sock = socket(PF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        fprintf(stderr, "socket failed");
        exit(1);
    }
    int optval = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof optval);

    struct sockaddr_in addr = {};
    int port = 8081;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = INADDR_ANY;
    r = bind(sock, (struct sockaddr*)&addr, sizeof(addr));
    assert(r >= 0);
    r = listen(sock, 1);
    assert(r >= 0);

    struct sock_info si;
    si.sock = sock;
    ioh_event_init_fd(&si.event, sock);
    aio_add_wait_object(&si.event, got_client, &si);
#endif




    //uint8_t buf[8 * 512] = {1,};
    //swap_aio_write(&bs, 1, buf, 8, write_done, NULL);
    for (;;) {
        aio_wait();
    }
    return 0;
}
