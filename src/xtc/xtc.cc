#include "../../include/xtc/xtc.hh"
#include "../../x86disass/disass.hpp"
extern "C" {
#include "../../x86disass/disass.h"
};

#define _PFX_ADDR (1)
#define _PFX_OPER (2)
#define _PFX_REX (0xf << 2)

__u64 x_t_c::xtc_insert(__u16 tabl_ndx, instr *in, __u64 off) {
    __u64 orig_off = off;
    xtc_ehdr *ehdr = gets_ehdr(tabl_ndx, off);
    assert((!!ehdr));

    for (__u8 i = 0; i < 0b1000000; i++) {
        __u8 sc[15]{0};
        __u8 pfx_len = 0;
        struct xtc_instr x = {
            .tabl_ndx = tabl_ndx,
        };

        _defer([&] {
            f.pwrite(&x, sizeof(struct xtc_instr), off);
            off += sizeof(struct xtc_instr);
            ehdr->count++;
        });

        if (i & _PFX_ADDR) {
            x.pfx.addr = (sc[pfx_len++] = 0x67);
        }
        if (i & _PFX_OPER) {
            x.pfx.oper = (sc[pfx_len++] = 0x66);
        }
        if (i & _PFX_REX) {
            x.pfx.rex = (sc[pfx_len++] = 0x40 | (i >> 2));
        }
        _build_instr(&x86_64_tabl[tabl_ndx], &sc[pfx_len]);

        auto &insn = d.disass(sc);
        if (insn.insn != in)
            continue;

        foreach_operand(p, &insn) {
            int t = 0;

            if (p->rip || p->is_ptr)
                t = X86_OP_PTR; // Pointer
            else if (p->is_imm)
                t = X86_OP_IMM; // Immediate
            else if (p->reg)
                t = X86_OP_REG; // Register

            *(reinterpret_cast<int *>(&x.op[x.op_count].t)) = t;
            x.op[x.op_count++].size = ((!!p->sz) ? p->sz : p->disp_sz);
        }
    }

    return off - orig_off;
}