#include "../llist.h"
#include "../pe64/pe64.h"
#include "../types.h"
#include "./rel_yayo.h"
#include <windows.h>

#ifndef _1DLSD_H
#define _1DLSD_H
#define LSD_API

typedef unsigned long long LSD_STATUS;

enum LSD_STATUS_COdE {
    LSD_OK,
    LSD_NULLPTR,
};

enum _1DLSD_IMAGE_TYPE {
    EXE = IMAGE_FILE_EXECUTABLE_IMAGE,
    DLL = IMAGE_FILE_EXECUTABLE_IMAGE | IMAGE_FILE_DLL,
};

enum _1DLSD_TYPE {
    NullHdr = 0x0,
    PAGE_R = 0x100,
    PAGE_RW = 0x200,
    PAGE_RX = 0x400,
    PAGE_RWX = 0x700,
    DosHdr = 0x10,
    DosStub = 0x20,
    NtHdrs = 0x30,
    // Sign	= 0x100,
    // FileHdr	= 0x200,
    // OptHdr	= 0x400,
    SecHdr = 0x40,
    Section = 0x50,
    DataDir = 0x60,
    SEC_text,
    SEC_data,
    SEC_rdata,
    SEC_bss,
    SEC_idata,
    SEC_edata,
    SEC_reloc,
    SEC_rsrc,
    SEC_tls,
    SEC_pdata,
    SEC_xdata,
    SEC_debug,
    SEC_CRT,
    SEC_gfids,
    SEC_didat,
    SEC_sxdata,
    SEC_00cfg,
    SEC_gehcont,
    SEC_orpc,
    SEC_arch,
    SEC_drectve,
};

// fuck hdr, only entry
struct _1Dlsd_entry {
    _1DLSD_TYPE t;
    mm_t *mm;
    struct {
        pe64_image *pe;
        __u64 off, sz;
    } src;
    struct {
        __u64 off, sz;
    } dst;
};

struct _1Dlsd_st {
    LLIST_OF(pe64_image *) pImg;
    LLIST_OF(_1Dlsd_entry) px;
};
#endif
