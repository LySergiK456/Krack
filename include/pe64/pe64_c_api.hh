#include "../conf.hh"
#include "./pe64.hh"
extern "C" {
    #include "../mem.h"
    #include "./pe64.h"
};

#ifndef KRACK_PE64_C_API_HH
#define KRACK_PE64_C_API_HH
typedef struct _pe64_image {
    PE64 bin;

    __u8                    *&pMem{bin.pMem};
    pe64_hdr_t              dos;
    pe64_hdr_t              dos_stub;
    pe64_hdr_t              nt;
    std::vector<pe64_hdr_t> sechdr;
    std::vector<pe64_hdr_t> sections;

    _pe64_image(char *file, char *symtab_dir) : bin(PE64(file, symtab_dir)) {
        assert(bin.ok != -1);
        dos = (pe64_hdr_t){
            {
                (void *)bin.dos,
                MM_NONE,
                sizeof(IMAGE_DOS_HEADER)
            }, 0
        };
        dos_stub = (pe64_hdr_t){
            {
                (void*)(&bin.pMem[sizeof(IMAGE_DOS_HEADER)]),
                MM_NONE,
                bin.dos->e_lfanew - sizeof(IMAGE_DOS_HEADER)
            }, sizeof(IMAGE_DOS_HEADER)
        };
        nt = (pe64_hdr_t){
            {
                (void *)bin.nt,
                MM_NONE,
                sizeof(IMAGE_NT_HEADERS)
            }, bin.dos->e_lfanew
        };

        __u32 i{};
        PE_EACH_SEC(&bin, sec) {
            sechdr.push_back((pe64_hdr_t){
                {
                    sec,
                    MM_NONE,
                    sizeof(IMAGE_SECTION_HEADER)
                }, bin.dos->e_lfanew
                    + sizeof(IMAGE_NT_HEADERS)
                    + (i++) * sizeof(IMAGE_SECTION_HEADER)
            });

            sections.push_back((pe64_hdr_t){
                {
                    (void*)&bin.pMem[sec->PointerToRawData],
                    MM_NONE,
                    sec->SizeOfRawData,
                }, sec->PointerToRawData
            });
        }
    }
} pe64_image;

extern "C" {
#include "./pe64.h"
};

#endif
