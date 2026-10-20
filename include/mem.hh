#include "./types.h"
#include "./utils.h"
#include "./mem.h"
#include <assert.h>

#ifndef KRACK_MEM_HH
#define KRACK_MEM_HH
struct mem_map_t {
    __u64 addr;
    __u64 size;
    __u32 perm;
    char *name{};

    mem_map_t() = delete;
    mem_map_t(char *_name, __u64 _addr, __u64 _sz, __u32 _perm)
        : addr{_addr}, size{_sz}, perm{_perm} {
        if (!!_name) {
            name = reinterpret_cast<char *>(xmalloc(strlen(_name) + 1));
            memcpy(name, _name, strlen(_name) + 1);
        }
    }
};

struct shadow_mem_t {
    void *addr;
    __u64 size;
    __u32 perm;
    mem_map_t *uc_mem;

    // shadow_mem_t() = default;
    void *ptr(__u64 virt) {
        if (!addr || !uc_mem->addr)
            return NULL;
        if (uc_mem->addr + uc_mem->size == virt)
            return addr + size;

        __u64 v = (__u64)addr + (virt - uc_mem->addr);

        assert(_contain_(reinterpret_cast<__u64>(addr), size, v));
        return reinterpret_cast<void *>(v);
    }

    bool IsX() {
        return perm & PAGE_EXECUTE_READWRITE || perm & PAGE_READWRITE;
    }
};
#endif