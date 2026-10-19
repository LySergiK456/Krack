#include "../types.h"
#include <unicorn/unicorn.h>
extern "C" {
#include "../mem.h"
};

#ifndef KRACK_UC_HH
#define KRACK_UC_HH

enum class X86Reg : __u64 {
    rax = UC_X86_REG_RAX,
    rbx = UC_X86_REG_RBX,
    rcx = UC_X86_REG_RCX,
    rdx = UC_X86_REG_RDX,
    rdi = UC_X86_REG_RDI,
    rsi = UC_X86_REG_RSI,
    rsp = UC_X86_REG_RSP,
    rbp = UC_X86_REG_RBP,
    r8 = UC_X86_REG_R8,
    r9 = UC_X86_REG_R9,
    r10 = UC_X86_REG_R10,
    r11 = UC_X86_REG_R11,
    r12 = UC_X86_REG_R12,
    r13 = UC_X86_REG_R13,
    r14 = UC_X86_REG_R14,
    r15 = UC_X86_REG_R15,
    rip = UC_X86_REG_RIP,
    eax = UC_X86_REG_EAX,
    ebx = UC_X86_REG_EBX,
    ecx = UC_X86_REG_ECX,
    edx = UC_X86_REG_EDX,
    edi = UC_X86_REG_EDI,
    esi = UC_X86_REG_ESI,
    esp = UC_X86_REG_ESP,
    ebp = UC_X86_REG_EBP,
};

namespace Uc {
__u64 reg(uc_engine *uc, X86Reg reg);
uc_err reg_wr(uc_engine *uc, X86Reg reg, __u64 v);
uc_err read(uc_engine *uc, __u64 addr, void *data, __u64 size);
__u64 read_u64(uc_engine *uc, __u64 addr);
uc_mem_region get_map(uc_engine *uc, __u64 addr);
uc_mem_region get_map_next(uc_engine *uc, __u64 addr);
}; // namespace Uc

__u32 uc_perm(__u32 perm);

#define _uc_ok(err) ((err) == UC_ERR_OK)
#define _uc_okay(err, ok)                                                      \
    ({                                                                         \
        ok = (((err) == UC_ERR_OK) ? 0 : -1);                                  \
        ((err) == UC_ERR_OK);                                                  \
    })

#define _uc_assert(err)                                                        \
    ({                                                                         \
        if (!_uc_ok(err)) {                                                    \
            puts(uc_strerror((err)));                                          \
            exit(-1);                                                          \
        }                                                                      \
    })
#endif
