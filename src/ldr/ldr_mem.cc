#include "../../include/conf.hh"
#include "../../include/syp/sype.hh"
#include "../../include/syp/uc.hh"
#include <assert.h>
#include <type_traits>
#include <windows.h>

template <typename P> static int _write_value(P *addr, auto v);

static __u64 heap_off = 0;
namespace SlitYerPE {
__u64 Ldr::uc_malloc(__u64 size) {
    if (!size) return 0;

    __u64 virt = HEAP_ADDR + heap_off;
    const __u64 end = virt + size;
    const __u64 next_off = heap_off + size;

    if (end < virt || next_off < heap_off)
        return 0;

    const __u64 map_begin = PAGE_ALIGN_UP(virt);
    const __u64 map_end = PAGE_ALIGN_UP(end);
    if (map_begin < virt || map_end < end || map_end < map_begin)
        return 0;

    if (map_end > map_begin) {
        uc_err err = mmap(map_begin, map_end - map_begin, UC_PROT_RW);
        if (!_uc_ok(err))
            return 0;
    }

    heap_off = next_off;
 
    return virt;
}
};

namespace SlitYerPE {
template uc_err Ldr::mwrite<void *>(__u64 addr, void *v);
template uc_err Ldr::mwrite<void **>(__u64 addr, void **v);
template uc_err Ldr::mwrite<__u64>(__u64 addr, __u64 v);
template uc_err Ldr::mwrite<long long>(__u64 addr, long long v);
template uc_err Ldr::mwrite<__u32>(__u64 addr, __u32 v);
template uc_err Ldr::mwrite<int>(__u64 addr, int v);
template uc_err Ldr::mwrite<__u16>(__u64 addr, __u16 v);
template uc_err Ldr::mwrite<short>(__u64 addr, short v);
template uc_err Ldr::mwrite<__u8>(__u64 addr, __u8 v);
template uc_err Ldr::mwrite<char>(__u64 addr, char v);

template uc_err Ldr::mcopy<void *>(__u64 addr, void *v);
template uc_err Ldr::mcopy<void **>(__u64 addr, void **v);
template uc_err Ldr::mcopy<__u64>(__u64 addr, __u64 v);
template uc_err Ldr::mcopy<long long>(__u64 addr, long long v);
template uc_err Ldr::mcopy<__u32>(__u64 addr, __u32 v);
template uc_err Ldr::mcopy<int>(__u64 addr, int v);
template uc_err Ldr::mcopy<__u16>(__u64 addr, __u16 v);
template uc_err Ldr::mcopy<short>(__u64 addr, short v);
template uc_err Ldr::mcopy<__u8>(__u64 addr, __u8 v);
template uc_err Ldr::mcopy<char>(__u64 addr, char v);
};

namespace SlitYerPE {
    void Ldr::virt_map_fxd(__u64 addr, __u64 size, __u32 prot) {
        constexpr __u64 GRAN = 0x10000;
        const __u64 end = addr + size;
        if (!size || end < addr)
            return;

        for (__u64 cur = addr; cur < end;) {
            MEMORY_BASIC_INFORMATION mbi{};

            if (VirtualQuery(
                    reinterpret_cast<void *>(cur),
                    &mbi,
                    sizeof(mbi)) != sizeof(mbi))
                return;

            const __u64 region_end =
                reinterpret_cast<__u64>(mbi.BaseAddress) + mbi.RegionSize;

            const __u64 stop = std::min(end, region_end);
            if (stop <= cur)
                return;

            if (mbi.State == MEM_FREE) {
                const __u64 base = cur & ~(GRAN - 1);
                const __u64 alloc_end = (stop + GRAN - 1) & ~(GRAN - 1);

                if (!VirtualAlloc(
                        reinterpret_cast<void *>(base),
                        alloc_end - base,
                        MEM_RESERVE | MEM_COMMIT,
                        prot))
                    return;
            } else if (mbi.State == MEM_RESERVE) {
                if (!VirtualAlloc(
                        reinterpret_cast<void *>(cur),
                        stop - cur,
                        MEM_COMMIT,
                        prot))
                    return;
            } else if (mbi.State == MEM_COMMIT) {
                if (!VirtualProtect(
                        reinterpret_cast<void *>(cur),
                        stop - cur,
                        prot,
                        NULL))
                    return;
            }

            cur = stop;
        }
    }

    uc_err Ldr::uc_map_fxd(__u64 addr, __u64 size, __u32 prot) {
        const __u64 end = addr + size;
        if (!size || (addr & 0xfff) || (size & 0xfff) || end < addr)
            return UC_ERR_ARG;

        for (__u64 cur = addr; cur < end;) {

            auto mapped = Uc::get_map(uc, cur);

            if (!!mapped.begin) {
                __u64 stop = std::min(end, mapped.end + 1);
                if (stop <= cur)
                    return UC_ERR_ARG;

                uc_err err = uc_mem_protect(uc, cur, stop - cur, prot);
                if (!_uc_ok(err))
                    return err;

                cur = stop;
                continue;
            }

            auto next = Uc::get_map_next(uc, cur);
            __u64 stop = (!!next.begin) ? std::min(end, next.begin) : end;

            if (stop <= cur)
                return UC_ERR_ARG;

            uc_err err = uc_mem_map(uc, cur, stop - cur, prot);
            if (!_uc_ok(err))
                return err;
            cur = stop;
        }
        return UC_ERR_OK;
    }
};

namespace SlitYerPE {
uc_err Ldr::mmap(__u64 virt, __u64 size, __u32 p, char *name) {
    assert(!(virt & 0xfff) && !!size);
    uc_err err = uc_map_fxd(virt, size, p);
    if (!_uc_okay(err, ok))
        return err;

    auto mem = new mem_map_t(name, virt, size, p);
    assert(!!mem);
    pmem_maps.emplace_back(mem);

    auto sh_mem = new shadow_mem_t{(void *)(VIRT_SHADOW_BASE + virt), size,
                                   uc_perm(p), mem};
    assert(!!sh_mem);
    shadow.push_back(sh_mem);

    do {
        virt_map_fxd(reinterpret_cast<__u64>(sh_mem->addr), size, sh_mem->perm);
        _zero_memory(sh_mem->addr, sh_mem->size);
    } while (0);

    return UC_ERR_OK;
}

uc_err Ldr::mmap(__u64 virt, __u64 size, __u32 perm) {
    return mmap(virt, size, perm, (char *)NULL);
}

uc_err Ldr::mwrite(__u64 addr, auto v) {
    // using T = std::decay_t<decltype(v)>(v);
    uc_err err{UC_ERR_OK};
    static_assert(sizeof(v) <= sizeof(void**));
    err = uc_mem_write(uc, addr, (void *)&v, sizeof(v));
    if (!_uc_okay(err, ok))
        return err;

    auto sh_mem = VAtoShadow(addr);
    if (!sh_mem || !sh_mem->addr)
        return UC_ERR_NOMEM;

    if ((typeid(v) == typeid(void *) || typeid(v) == typeid(void **) ||
         typeid(v) == typeid(__u64) || typeid(v) == typeid(long long)) &&
        !!Uc::get_map(uc, *(__u64 *)&v).begin) {
        __u64 value{*(__u64 *)&v};

        auto v_sh_mem = VAtoShadow(value);
        if (!v_sh_mem) // case of passing map+size
            v_sh_mem = VAtoShadow(value - 1);

        if (!v_sh_mem || !v_sh_mem->addr)
            return UC_ERR_NOMEM;

        _write_value(sh_mem->ptr(addr), v_sh_mem->ptr(value));
    } else {
        _write_value(sh_mem->ptr(addr), v);
    }

    return err;
}

uc_err Ldr::mmemcpy(__u64 virt, void *ptr, __u64 size) {
    uc_err err{UC_ERR_OK};
    err = uc_mem_write(uc, virt, ptr, size);
    if (!_uc_okay(err, ok))
        return err;

    auto sh_mem = VAtoShadow(virt);
    if (!sh_mem || !sh_mem->addr)
        return UC_ERR_NOMEM;

    _write_mem(sh_mem->ptr(virt), ptr, size);

    return err;
}

uc_err Ldr::mcopy(__u64 virt, auto v) {
    uc_err err{UC_ERR_OK};
    err = uc_mem_write(uc, virt, (void *)&v, sizeof(v));
    if (!_uc_okay(err, ok))
        return err;

    auto sh_mem = VAtoShadow(virt);
    if (!sh_mem || !sh_mem->addr)
        return UC_ERR_NOMEM;

    _write_value(sh_mem->ptr(virt), v);

    return err;
}
};

namespace SlitYerPE {
shadow_mem_t *Ldr::VAtoShadow(__u64 virt) {
    for (auto sh_mem : shadow) {
        // printf("~>~>~>%llx %llx~~>~>>~\n", sh_mem->uc_mem->addr,
        // sh_mem->uc_mem->size, virt);
        if (!!_contain_(sh_mem->uc_mem->addr, sh_mem->uc_mem->size, virt)) {
            return sh_mem;
        }
    }
    return nullptr;
}
};

template <typename P> static int _write_value(P *addr, auto v) {
    // using T = std::decay_t<decltype(v)>(v);
    __u32 dw;

    if (!__wr_init(addr, PAGE_SIZE, &dw))
        return -1;
    do {
    	if (	typeid(v) == typeid(__u64)
    		||	typeid(v) == typeid(long long)
    		||	typeid(v) == typeid(void*)
    		||	typeid(v) == typeid(void**))
    	{
    		*(void**)addr = *(void**)&v;
    	}
    	else if (	typeid(v) == typeid(int)
    		||		typeid(v) == typeid(__u32))
    	{
    		*(int*)addr = *(int*)&v;
    	}
    	else if (	typeid(v) == typeid(short)
    		||		typeid(v) == typeid(__u16))
    	{
    		*(short*)addr = *(short*)&v;
    	}
    	else if (	typeid(v) == typeid(char)
    		||		typeid(v) == typeid(__u8))
    	{
    		*(char*)addr = *(char*)&v;
    	}
    	else
    	{
            memmove(addr, &v, sizeof(v));
    	}
    } while (0);
    if (!__wr_exit(addr, PAGE_SIZE, dw))
        return -1;

    return 0;
}

namespace SlitYerPE {
__u64 Ldr::AllocUcStr(char *str) {
    __u64 s_len = strlen(str) + 1;
    wchar_t wstr[0x200]{};

    for (__u64 i = 0; i < s_len; i++)
        wstr[i] = static_cast<__u16>(str[i]);

    return AllocUcStr(wstr);
}

__u64 Ldr::AllocUcStr(wchar_t *wstr) {
    __u64 len = wcslen(wstr) * sizeof(wchar_t);
    auto uni = (_UNICODE_STRING_ *)uc_malloc(sizeof(_UNICODE_STRING_));
    __u64 virt_buf = uc_malloc(len + 2);

    mwrite(&uni->Length, (__u16)(len));
    mwrite(&uni->MaximumLength, (__u16)(len + sizeof(wchar_t)));
    mwrite(&uni->Buffer, (void *)(virt_buf));
    mmemcpy(virt_buf, wstr, len);

    return reinterpret_cast<__u64>(uni);
}
};
