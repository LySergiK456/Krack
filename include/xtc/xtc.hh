#include "../conf.hh"
#include "../utils.hh"
#include <assert.h>
#include <vector>

#ifndef KRACK_XTC_HH
#define KRACK_XTC_HH
extern "C" {
#include "../types.h"
#include "../../x86disass/disass.h"
#include "./xtc.h"
};
#include "../../x86disass/disass.hpp"

#define X_T_C_DUMP_X8664

#define INSTR_X86_64_INVALID(in)                                               \
    (!(in) || !(in)->mnemonic || (in)->opcode1 == 0x0F ||                      \
     ((in)->prefix && !(in)->opcode1))

class x_t_c {
    Disass d;
    Util::outfile_t f;
    __u64 x_off{};
    xtc_fheader f_hdr{};
    std::vector<xtc_ehdr> ehdr_vec;

  public:
    x_t_c(char *outfile = XTC_DEFAULT_OUTFILE) : f(outfile) {
        __u64 off{};
        if (!f.ok())
            throw std::runtime_error("FUCK!");
        strcpy(f_hdr.type, X_T_C_X64_STR);
        off += sizeof(xtc_fheader);

        instr *in{}, *jn{};
        __u16 i{}, j{};
        for_each_instr(X86_64, in) {
            if (!INSTR_X86_64_INVALID(in)) {
                ehdr_vec.push_back({.tabl_ndx = i});
                f_hdr.e_count++;
                off += sizeof(xtc_ehdr);
            }
            i++;
        }

        /**
         * pWrite instr entries */
        for_each_instr(X86_64, jn) {
            if (!INSTR_X86_64_INVALID(jn))
                off += xtc_insert(j, jn, off);
            j++;
        }

        /**
         * Dump XTC-file & -(entry-header)'s */
        f.pwrite(&f_hdr, sizeof(xtc_fheader), 0);
        for (__u64 i = 0; i < f_hdr.e_count; i++) {
            __u64 e_size = sizeof(xtc_fheader) + i * sizeof(xtc_ehdr);
            f.pwrite(&ehdr_vec[i], sizeof(xtc_ehdr), e_size);
        }
    }

  private:
    __u64 xtc_insert(__u16 tabl_ndx, instr *in, __u64 off);

    xtc_ehdr *gets_ehdr(__u16 tabl_ndx, __u64 off) {
        for (auto &e : ehdr_vec)
            if (e.tabl_ndx == tabl_ndx) {
                e.offset = off;
                return &e;
            }

        return nullptr;
    }
};
#endif
