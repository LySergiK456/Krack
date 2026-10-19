#include "../../include/syp/uc.hh"
#include "../../include/utils.hh"
#include <assert.h>
extern "C" {
#include "../../include/utils.h"
};

__u64 Uc::reg(uc_engine *uc, X86Reg reg) {
    __u64 ret{};
    uc_err err = uc_reg_read(uc, static_cast<__u64>(reg), (void *)&ret);
#ifdef KRACK_UC_NOERR
    _uc_assert(err);
#endif
    return (!!_uc_ok(err)) ? ret : -1;
}

uc_err Uc::reg_wr(uc_engine *uc, X86Reg reg, __u64 v) {
    uc_err err = uc_reg_write(uc, static_cast<__u64>(reg), (void *)&v);
#ifdef KRACK_UC_NOERR
    _uc_assert(err);
#endif
    return err;
}

__u64 Uc::read_u64(uc_engine *uc, __u64 addr) {
    __u64 p{};
    uc_err err = Uc::read(uc, addr, (void *)&p, sizeof(__u64));
#ifdef KRACK_UC_NOERR
    _uc_assert(err);
#endif
    return (!!_uc_ok(err)) ? p : -1;
}

uc_err Uc::read(uc_engine *uc, __u64 addr, void *data, __u64 size) {
    uc_err err = uc_mem_read(uc, addr, data, size);
#ifdef KRACK_UC_NOERR
    _uc_assert(err);
#endif
    return err;
}
uc_mem_region Uc::get_map(uc_engine *uc, __u64 addr) {
    uc_mem_region *regs{};
    __u32 n{};

    if (!_uc_ok(uc_mem_regions(uc, &regs, &n)))
        return {0};

    for (__u32 i = 0; i < n; i++) {
        if (addr >= regs[i].begin && addr <= regs[i].end) {
            auto ret = regs[i];
            uc_free(regs);
            return ret;
        }
    }

    uc_free(regs);
    return {0};
}

uc_mem_region Uc::get_map_next(uc_engine *uc, __u64 addr) {
    uc_mem_region *regs{};
    __u32 n{};

    uc_err err = uc_mem_regions(uc, &regs, &n);
#ifdef KRACK_UC_NOERR
    _uc_assert(err);
#endif
    if (!_uc_ok(err))
        return {0};

    uc_mem_region next{};
    bool found = false;

    for (__u32 i = 0; i < n; i++) {
        if (regs[i].begin > addr && (!found || regs[i].begin < next.begin)) {
            next = regs[i];
            found = true;
        }
    }

    uc_free(regs);
    return ((!!found) ? next : uc_mem_region{0});
}

__u32 uc_perm(__u32 perm) {
    switch (perm) {
    case UC_PROT_R:
        return PAGE_READONLY;
    case UC_PROT_RWX:
        return PAGE_EXECUTE_READWRITE;
    case UC_PROT_RW:
        return PAGE_READWRITE;
    case UC_PROT_RX:
        return PAGE_EXECUTE_READ;
    }
    assert(0);
    return -1;
}