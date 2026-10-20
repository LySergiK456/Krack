#include "../types.h"
#include "../mem.h"

#ifndef KRACK_PE64_H
#define KRACK_PE64_H
typedef struct {
    union {
        mm_t mm;
        void *ptr;
    };
    __u64 off;
} pe64_hdr_t;

typedef struct _pe64_image pe64_image;
pe64_image *new_pe64(char *file);
#endif