#include "./types.h"

#ifndef KRACK_UTILS_H
#define KRACK_UTILS_H
#include <stdio.h>

#define prf printf
#define pr puts
#define xx(x) printf("0x%lx\n", (__u64)(x))

typedef enum {
    ErrOK = 0u,
    ErrNoDir = 1u,
    ErrNoFile = 2u,
    ErrCreateFile = 3u,
} perr_t;

const char *strerr(perr_t err);
void *xmalloc(__u64 size);
__u32 FileExists(char *file);
__u32 DirExists(char *dir);
void hexdump(void *addr, __u64 sz);
int __wr_init(void *addr, __u64 size, __u32 *dw);
int __wr_exit(void *addr, __u64 size, __u32 perm);
int _write_mem(void *dst, void *src, __u64 size);
int _zero_memory(void *dst, __u64 size);
int _write_memset(void *dst, int ch, __u64 size);
int _write_qwordptr(void *ptr, __u64 v);
int _write_dwordptr(void *addr, __u32 v);
int _write_uint16(void *addr, __u16 v);
__s8 _memcmp(void *a, void *b, __u64 size);
#endif
