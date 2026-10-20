#include <list>
#include <map>
#include <memory>
#include <vector>
extern "C" {
#include "../types.h"
};
#include "../mem.hh"
#include "../pe64/pe64.hh"
#include "../pe64/pe64_c_api.hh"

#ifndef _1DLSD_HH
#define _1DLSD_HH
#include "../../x86disass/disass.hpp"

extern "C" {
#include "./1dlsd.h"
#include "./rel_yayo.h"
};

namespace SlitYerPE {
class _1Dlsd;
struct lsd_pass {
  protected:
    _1Dlsd *lsd{nullptr};

  public:
    lsd_pass() = default;

    virtual LSD_STATUS _init_(_1Dlsd *lsd) {
        return LSD_OK;
    }

    friend class _1Dlsd;
};
};

using IMG_DOS_HEADER        = IMAGE_DOS_HEADER;
using IMG_NT_HEADERS        = IMAGE_NT_HEADERS;
using IMG_DATA_DIRECTORY    = IMAGE_DATA_DIRECTORY;
using IMG_SECTION_HEADER    = IMAGE_SECTION_HEADER;

namespace SlitYerPE {
struct Lyss {
    _1Dlsd          *lsd;
    pe64_image      &base_pe;

    std::map<__u64, struct _1Dlsd_entry>    map;

    Lyss(_1Dlsd *l, pe64_image &_pe) : lsd{l}, base_pe{_pe} {
        auto& pe = base_pe;
        push(&pe, DosHdr, pe.dos);
        push(&pe, DosStub,pe.dos_stub);
        push(&pe, NtHdrs, pe.nt);

        for (auto& sechdr : pe.sechdr)  push(&pe, SecHdr, sechdr);
        for (auto& sec : pe.sections)   push(&pe, Section, sec);
        initSections();
    }
    Generic(T) void push(pe64_image *pe, enum _1DLSD_TYPE t, T &v) {
        map[v.off] = (struct _1Dlsd_entry){
            .t = t, .mm = &v.mm, .src = {pe, v.off, v.mm.sz}};
    }
    Generic(Fn) int feach(enum _1DLSD_TYPE &t, Fn fn) {
        return feach(t, nullptr, fn);
    }
    Generic(Fn) int feach(enum _1DLSD_TYPE &t, struct _1Dlsd_entry *v, Fn fn) {
        int i = 0;
        try {
            for (auto &[_, e] : map)
                if (e.t == t && ++i && !!e.mm) {
                    if (!!v) *v = e;
                    for (__u64 off = 0, sz = get_size(t); off < e.mm->sz; off += sz) {
                        fn(static_cast<lambda_arg<decltype(fn)>>(e.mm->mem+off));
                    }
                }
        } catch (...) {}

        return i;
    }
    std::map<__u64, struct _1Dlsd_entry> &operator()() { return map; }
    __u64 get_size(enum _1DLSD_TYPE &t) {
        __u64 v = 0;
        switch (t) {
            case DosHdr: v = sizeof(IMG_DOS_HEADER);     break;
            case NtHdrs: v = sizeof(IMG_NT_HEADERS);     break;
            case DataDir:v = sizeof(IMG_DATA_DIRECTORY); break;
            case Section:v = sizeof(IMG_SECTION_HEADER); break;
        }
        return v;
    }

private:
    void initSections();
};

class _1Dlsd : public _1Dlsd_st {
    Disass          d;
    lsd_pass        &pass;
    Lyss            lyss;

  public:
    _1Dlsd(pe64_image &base_pe, lsd_pass &_p);
    __s8 make(char *f);
};
};
#endif
