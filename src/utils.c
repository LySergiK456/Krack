#include "../include/utils.h"
#include "../include/mem.h"
#include <assert.h>
#include <windows.h>

const char *strerr(perr_t err) {
    switch (err) {
    case ErrOK:
        return "Success";

    case ErrNoDir:
        return "No such directory";

    case ErrNoFile:
        return "No such file";

    default:
        return "Unknown Error";
    }
}

void *xmalloc(__u64 size) {
    void *ptr = malloc(size);
    assert(!!ptr);
    memset(ptr, 0, size);
    return ptr;
}

__u32 FileExists(char *file) {
    __u32 dwAttr = GetFileAttributes(file);
    return (dwAttr != INVALID_FILE_ATTRIBUTES &&
            !(dwAttr & FILE_ATTRIBUTE_DIRECTORY));
}

__u32 DirExists(char *dir) {
    __u32 dwAttr = GetFileAttributes(dir);
    return (dwAttr != INVALID_FILE_ATTRIBUTES &&
            !!(dwAttr & FILE_ATTRIBUTE_DIRECTORY));
}

void hexdump(void *addr, __u64 sz) {
    __u8 *ptr = (__u8 *)addr;

    for (__u64 i = 0; i <= sz; i++) {
        __u8 ch = ptr[i];

        if ((!(i % 0x10) && i) || i >= sz) {
            __u8 n = 0x10;

            if (i >= sz) {
                n = !(sz % 0x10) ? 0x10 : (sz % 0x10);
                for (int x = n; x < 0x10; x++) {
                    if (!(i % 4))
                        prf("  ");
                    prf("   ");
                }
            }

            prf("\t|\t");

            for (__u8 l = 0; l < n; l++) {
                __u8 c = ptr[(i - n) + l];
                prf("%c", isprint(c) ? c : '.');
            }

            pr("");
            if (i >= sz)
                return;
        }

        if (!i || !(i % 0x10))
            prf("0x%06x :\t", i);

        if (!(i % 4) && i && (i % 0x10))
            prf("| ");

        prf("%02x ", ch);
    }
}

int __wr_init(void *addr, __u64 size, __u32 *dw) {
    return VirtualProtect(PAGE_ALIGN_DOWN(addr), PAGE_ALIGN_UP(size),
                          PAGE_READWRITE, dw);
}

int __wr_exit(void *addr, __u64 size, __u32 perm) {
    return VirtualProtect(PAGE_ALIGN_DOWN(addr), PAGE_ALIGN_UP(size), perm,
                          NULL);
}

int _write_mem(void *dst, void *src, __u64 size) {
    __u32 dw;
    if (!dst || !src)
        return -1;

    if (!__wr_init(dst, size, &dw))
        return -1;
    memcpy(dst, src, size);
    if (!__wr_exit(dst, size, dw))
        return -1;

    return 0;
}

int _zero_memory(void *dst, __u64 size) { return _write_memset(dst, 0, size); }

int _write_memset(void *dst, int ch, __u64 size) {
    __u32 dw;
    if (!dst)
        return -1;

    if (!__wr_init(dst, size, &dw))
        return -1;
    memset(dst, ch, size);
    if (!__wr_exit(dst, size, dw))
        return -1;

    return 0;
}

int _write_uint16(void *addr, __u16 v) {
    __u32 dw;
    if (!__wr_init(addr, PAGE_SIZE, &dw))
        return -1;
    *(__u16 *)addr = v;
    if (!__wr_exit(addr, PAGE_SIZE, dw))
        return -1;

    return 0;
}

int _write_dwordptr(void *addr, __u32 v) {
    __u32 dw;
    if (!__wr_init(addr, PAGE_SIZE, &dw))
        return -1;
    *(__u32 *)addr = v;
    if (!__wr_exit(addr, PAGE_SIZE, dw))
        return -1;

    return 0;
}

int _write_qwordptr(void *addr, __u64 v) {
    __u32 dw;
    if (!__wr_init(addr, PAGE_SIZE, &dw))
        return -1;
    *(void **)addr = v;
    if (!__wr_exit(addr, PAGE_SIZE, dw))
        return -1;

    return 0;
}

__s8 _memcmp(void *a, void *b, __u64 size) {
    for (__u64 i = 0; i < size; i++)
        if (((char *)a)[i] != ((char *)b)[i])
            return -1;

    return 0;
}
