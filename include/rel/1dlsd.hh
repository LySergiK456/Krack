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

    virtual LSD_STATUS _init_() { return LSD_OK; }

    friend class _1Dlsd;
};
}; // namespace SlitYerPE

using IMG_DOS_HEADER = IMAGE_DOS_HEADER;
using IMG_NT_HEADERS = IMAGE_NT_HEADERS;
using IMG_DATA_DIRECTORY = IMAGE_DATA_DIRECTORY;
using IMG_SECTION_HEADER = IMAGE_SECTION_HEADER;

namespace SlitYerPE {
class Lyss {
    _1Dlsd *lsd;
    pe64_image &base_pe;

  public:
    std::map<__u64 *, struct _1Dlsd_entry> map; // pointing to pe structs
    std::map<__u64, struct _1Dlsd_entry>
        seg; // 'segments' in between the headers

    Lyss(_1Dlsd *l, pe64_image &_pe) : lsd{l}, base_pe{_pe} {
        push(&base_pe, DosHdr, base_pe.dos);
        push(&base_pe, NtHdrs, base_pe.nt);
    }
    Generic(T) void push(pe64_image *pe, enum _1DLSD_TYPE t, T &v) {
        map[&v.off] = (struct _1Dlsd_entry){
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
                    if (!!v)
                        *v = e;
                    for (__u64 off = 0, sz = get_size(t); off < e.mm->sz;
                         off += sz)
                        fn(static_cast<lambda_arg<decltype(fn)>>(e.mm->mem +
                                                                 off));
                }
        } catch (...) {
        }
        return i;
    }
    std::map<__u64 *, struct _1Dlsd_entry> &operator()() { return map; }
    __u64 get_size(enum _1DLSD_TYPE &t) {
        __u64 v = 0;
        switch (t) {
        case DosHdr:
            v = sizeof(IMG_DOS_HEADER);
            break;
        case NtHdrs:
            v = sizeof(IMG_NT_HEADERS);
            break;
        case DataDir:
            v = sizeof(IMG_DATA_DIRECTORY);
            break;
        case SecHdr:
            v = sizeof(IMG_SECTION_HEADER);
            break;
        }
        return v;
    }
};

class _1Dlsd : public _1Dlsd_st {
    Disass d;
    lsd_pass &pass;
    Lyss lyss;

  public:
    _1Dlsd(pe64_image &base_pe, lsd_pass &_p);
};
}; // namespace SlitYerPE
#endif
