#include "../conf.hh"
#include "../utils.hh"
#include <fileapi.h>
#include <stdio.h>
#include <string.h>
#include <windows.h>
#include <winternl.h>
extern "C" {
#include "../types.h"
#include "../mem.h"
#include "../utils.h"
};
#include <list>
#include <memory>

#ifndef KRACK_PE64_HH
#define KRACK_PE64_HH

#define _DATA_DIR_ST(T, name)                                                  \
    struct {                                                                   \
        IMAGE_DATA_DIRECTORY *DataDir;                                         \
        T *name;                                                               \
    }

typedef enum { PE64_SYM_T = 1u, PE64_SYM_EXPORT_T = 2u } _SYMBOL_TYPE_;

struct PE64_SYMBOL {
    _SYMBOL_TYPE_ t;
    IMAGE_SYMBOL *img_sym;
    char *name;
    __u32 name_off;
    __u32 rva;
    __u32 off;
    __u32 size;
    __u32 exp_ndx;
    /* import / export */
};

enum class PE32_FLAGS : __u8 {
    BITS_32 = 32,
    BITS_64 = 64,
};

struct PE64 {
    PE32_FLAGS bits;
    struct {
        HANDLE hMap;
        __u64 size;
        union {
            void *lpName;
            char *lpcName;
            char *name;
        };
        char *shortname;
    } f;
    union {
        void *pMap{0};
        IMAGE_DOS_HEADER *dos;
        __u8 *pMem;
    };
    union {
        IMAGE_NT_HEADERS *nt;
        IMAGE_NT_HEADERS *nt64;
        IMAGE_NT_HEADERS32 *nt32;
    };
    IMAGE_SECTION_HEADER *section;
    Util::MMap_t<PE64_SYMBOL> symbols;

    _DATA_DIR_ST(IMAGE_IMPORT_DESCRIPTOR, Desc) imp;
    struct {
        IMAGE_DATA_DIRECTORY *DataDir;
        IMAGE_EXPORT_DIRECTORY *Dir;
        __u32 *Func;
        __u32 *Name;
        __u16 *Ords;

    } exp;
    _DATA_DIR_ST(IMAGE_BASE_RELOCATION, entries) rel;

    __s8 ok{0};

    PE64() = default;
    PE64(PE64 *) = delete;
    PE64(const PE64 &) = delete;
    PE64(PE64 &&) = delete;

    PE64 &operator=(const PE64 &) = delete;
    PE64 &operator=(PE64 &&) = delete;
    // PE64& operator=(PE64&& r) = default;
    // PE64(PE64 *pe) {
    // 	memmove(this, std::move(pe), sizeof(PE64));
    // }

    PE64(const char *file) : PE64(const_cast<char *>(file), nullptr) {}

    PE64(const char *file, const char *symtab_dir)
        : PE64(const_cast<char *>(file), const_cast<char *>(symtab_dir)) {}

    PE64(char *file) : PE64(file, nullptr) {}
    PE64(char *file, char *symtab_dir);

    bool rva_is_overflow(__u32 rva);
    bool off_is_overflow(__u32 off);
    __u64 base();
    // IMAGE_SYMYBOL *sym_by_rva(__u32 rva) {
    void *rva_to_ptr(__u32 rva);
    __s64 rva_to_off(__u32 rva);
    void *va_to_ptr(__u64 rva);
    __s64 va_to_off(__u64 rva);
    __s64 off_to_rva(__u64 off);
    PE64_SYMBOL *rva_to_sym(__u32 rva);
    PE64_SYMBOL *name_to_sym(char *name);

    ~PE64() {
        if (!!pMap)
            UnmapViewOfFile(pMap);
        if (HANDLE_OK(f.hMap))
            CloseHandle(f.hMap);
    }

  private:
    __s8 _Load();
    void ParseIAT();
    void ParseReloc();
    void ParseEAT();
    void InitSymtab();
    perr_t LoadSymtabFromDir(char *dir);
    perr_t SaveSymtab(char *dir);
    __u32 rva_sym_size(__u32 rva);
};

struct pe_section : IMAGE_SECTION_HEADER {
    DWORD &Virt{VirtualAddress};
    DWORD &Off{PointerToRawData};
    DWORD &FileSize{SizeOfRawData};
    DWORD &VirtSize{Misc.VirtualSize};
    bool isR{};
    bool isW{};
    bool isX{};

    pe_section(IMAGE_SECTION_HEADER &sec) : IMAGE_SECTION_HEADER(sec) {
        isR = Characteristics & IMAGE_SCN_MEM_READ;
        isW = Characteristics & IMAGE_SCN_MEM_WRITE;
        isX = Characteristics & IMAGE_SCN_MEM_EXECUTE;
    };
};

struct pe_imports : IMAGE_IMPORT_DESCRIPTOR {
    IMAGE_THUNK_DATA64 *ILT{};
    IMAGE_THUNK_DATA64 *IAT{};
    char *name{};

    pe_imports(PE64 &pe, IMAGE_IMPORT_DESCRIPTOR &desc)
        : IMAGE_IMPORT_DESCRIPTOR(desc) {
        name = reinterpret_cast<char *>(pe.rva_to_ptr(Name));
        __u32 rva =
            (!!OriginalFirstThunk) ? (OriginalFirstThunk) : (FirstThunk);
        ILT = (IMAGE_THUNK_DATA64 *)pe.rva_to_ptr(rva);
        IAT = (IMAGE_THUNK_DATA64 *)pe.rva_to_ptr(FirstThunk);
    }
};

extern "C" {
typedef struct {
    __u32 num_of_syms;
    __u32 header_size;
} dat_symtab_t;
};

struct PE64_IMAGE {
    PE64 bin;
    __u64 virt{};
    __u64 size{};
    // __u32		perm;

    PE64_IMAGE() = delete;
    // PE64_IMAGE(PE64_IMAGE *pe_img) : bin(&pe_img->bin) {
    // 	memmove(this, pe_img, sizeof(PE64_IMAGE));
    // }
    PE64_IMAGE(PE64_IMAGE *) = delete;
    PE64_IMAGE(PE64 &&) = delete;
    // PE64_IMAGE(PE64&& _pe)
    // 	: bin{std::move(_pe)}, size{_pe.nt->OptionalHeader.SizeOfImage},
    // virt{reinterpret_cast<__u64>(_pe.base())} {}

    PE64_IMAGE(char *file, char *symtab_dir) : bin(file, symtab_dir) {
        if (bin.ok != -1) {
            size = bin.nt->OptionalHeader.SizeOfImage;
            virt = reinterpret_cast<__u64>(bin.nt->OptionalHeader.ImageBase);
        }
    }

    PE64_IMAGE(char *file) : bin(file) {
        if (bin.ok != -1) {
            size = bin.nt->OptionalHeader.SizeOfImage;
            virt = reinterpret_cast<__u64>(bin.nt->OptionalHeader.ImageBase);
        }
    }

    void *rva_to_ptr(__u32 rva);
    void *va_to_ptr(__u64 rva);
    __s64 va_to_off(__u64 va);
};

#define PE_EACH_SEC(pe, _sec)                                                  \
    for (IMAGE_SECTION_HEADER *_sec = (pe)->section;                           \
         _sec < &(pe)->section[(pe)->nt->FileHeader.NumberOfSections]; _sec++)

#define PE_EACH_XSEC(pe, _sec)                                                 \
    PE_EACH_SEC(pe, __##_sec)                                                  \
    for (pe_section _ptr_##_sec(*__##_sec), *_sec = &_ptr_##_sec; !!_sec;      \
         _sec = nullptr)

#define PE_EACH_IMPORT(pe, desc)                                               \
    if (!!(pe) && !!(pe)->imp.DataDir->VirtualAddress)                         \
        for (IMAGE_IMPORT_DESCRIPTOR *desc = (pe)->imp.Desc;                   \
             (!!desc && !!desc->Name); desc++)

#define PE_EACH_XIMPORT(pe, _desc)                                             \
    PE_EACH_IMPORT(pe, __##_desc)                                              \
    for (pe_imports _ptr_##_desc(*(pe), *__##_desc), *_desc = &_ptr_##_desc;   \
         !!_desc; _desc = nullptr)

#define _PE_EACH_EXPORT(pe, i)                                                 \
    for (__u32 i = 0; i < (pe)->exp.Dir->NumberOfNames; i++)

#define PE_EACH_EXPORT(pe, i)                                                  \
    if (!!(pe)->exp.DataDir->VirtualAddress)                                   \
    _PE_EACH_EXPORT(pe, i)                                                     \
    if ((pe)->exp.Ords[i] < (pe)->exp.Dir->NumberOfFunctions)

#define PE_EACH_RELOC(pe, r)                                                   \
    if (!!(pe)->rel.DataDir->VirtualAddress)                                   \
        for (IMAGE_BASE_RELOCATION *r = (pe)->rel.entries;                     \
             (__u64)r <                                                        \
                 ((__u64)(pe)->rel.entries + (pe)->rel.DataDir->Size) &&       \
             !!r->VirtualAddress && !!r->SizeOfBlock;                          \
             r = (IMAGE_BASE_RELOCATION *)((__u8 *)r + r->SizeOfBlock))

#define PE_EACH_RELOC_ENTRY(r, i)                                              \
    for (__u16 *_i = (__u16 *)&(r)[1], i = 1;                                  \
         (!!_i && (__u64)_i < (__u64)(r) + (r)->SizeOfBlock) &&                \
         ((i = *_i) || 1);                                                     \
         _i++)

#define PE_EACH_SYMBOL(pe, sym)                                                \
    if (!!(pe)->nt->FileHeader.PointerToSymbolTable)                           \
        for (IMAGE_SYMBOL                                                      \
                 *sym =                                                        \
                     (IMAGE_SYMBOL *)(&(pe)->pMem[(pe)->nt->FileHeader         \
                                                      .PointerToSymbolTable]), \
                 *end =                                                        \
                     &((IMAGE_SYMBOL *)&(pe)                                   \
                           ->pMem[(pe)->nt->FileHeader.PointerToSymbolTable])  \
                         [(pe)->nt->FileHeader.NumberOfSymbols];               \
             (__u64)sym < (__u64)end; sym += 1 + sym->NumberOfAuxSymbols)

#define PE64_SYM_IS_SEC(pe, sym)                                               \
    (!!sym->SectionNumber &&                                                   \
     sym->SectionNumber <= (pe)->nt->FileHeader.NumberOfSections)

#endif
