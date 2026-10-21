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

constexpr __u64 IMG_DIR_EXPORT        = IMAGE_DIRECTORY_ENTRY_EXPORT;
constexpr __u64 IMG_DIR_IMPORT        = IMAGE_DIRECTORY_ENTRY_IMPORT;
constexpr __u64 IMG_DIR_RESOURCE      = IMAGE_DIRECTORY_ENTRY_RESOURCE;
constexpr __u64 IMG_DIR_EXCEPTION     = IMAGE_DIRECTORY_ENTRY_EXCEPTION;
constexpr __u64 IMG_DIR_SECURITY      = IMAGE_DIRECTORY_ENTRY_SECURITY;
constexpr __u64 IMG_DIR_BASERELOC     = IMAGE_DIRECTORY_ENTRY_BASERELOC;
constexpr __u64 IMG_DIR_DEBUG         = IMAGE_DIRECTORY_ENTRY_DEBUG;
constexpr __u64 IMG_DIR_ARCHITECTURE  = IMAGE_DIRECTORY_ENTRY_ARCHITECTURE;
constexpr __u64 IMG_DIR_GLOBALPTR     = IMAGE_DIRECTORY_ENTRY_GLOBALPTR;
constexpr __u64 IMG_DIR_TLS           = IMAGE_DIRECTORY_ENTRY_TLS;
constexpr __u64 IMG_DIR_LOAD_CONFIG   = IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG;
constexpr __u64 IMG_DIR_BOUND_IMPORT  = IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT;
constexpr __u64 IMG_DIR_IAT           = IMAGE_DIRECTORY_ENTRY_IAT;
constexpr __u64 IMG_DIR_DELAY_IMPORT  = IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT;
constexpr __u64 IMG_DIR_COM_DESCRIPTOR= IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR;

namespace SlitYerPE {
struct Lyss {
private:
    std::vector<pe64_hdr_t*>    tofree;
public:
    _1Dlsd          *lsd;
    pe64_image      &base_pe;

    std::map<__u64, struct _1Dlsd_entry>    map;
    Lyss&           self{*this};

    Lyss(_1Dlsd *l, pe64_image &_pe);
    ~Lyss();
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

    pe64_hdr_t *&operator<<(pe64_hdr_t&& v) {
        auto v_ptr = new pe64_hdr_t;
        *v_ptr = std::move(v);
        tofree.push_back(v_ptr);
        return tofree.back();
    }

    void AlignHeaders(__u64 off, __u64 sz);
private:
    void ChopSections();
    void ChopSegments();
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
