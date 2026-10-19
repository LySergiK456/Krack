#include "../conf.hh"
#include "./pe64.hh"
extern "C" {
#include "../mem.h"
};

#ifndef KRACK_PE64_C_API_HH
#define KRACK_PE64_C_API_HH

typedef struct {
    union {
        mm_t mm;
        void *ptr;
    };
    __u64 off;
} pe64_hdr_t;

typedef struct _pe64_image {
    PE64 bin;
    pe64_hdr_t dos;
    pe64_hdr_t nt;

    _pe64_image(char *file, char *symtab_dir) : bin(PE64(file, symtab_dir)) {
        dos = (pe64_hdr_t){{(void *)bin.dos, MM_NONE, sizeof(IMAGE_DOS_HEADER)},
                           0};
        nt = (pe64_hdr_t){{(void *)bin.nt, MM_NONE, sizeof(IMAGE_NT_HEADERS)},
                          bin.dos->e_lfanew};
    }
} pe64_image;

extern "C" {
#include "./pe64.h"
};

#endif
