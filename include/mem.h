#include <fileapi.h>
#include <windows.h>
#include <winternl.h>

#ifndef KRACK_MEM_H
#define KRACK_MEM_H
typedef struct {
    __u64 rax;
    __u64 rbx;
    __u64 rcx;
    __u64 rdx;
    __u64 rdi;
    __u64 rsi;
    __u64 rsp;
    __u64 rbp;
    __u64 r8;
    __u64 r9;
    __u64 r10;
    __u64 r11;
    __u64 r12;
    __u64 r13;
    __u64 r14;
    __u64 r15;
    __u64 rip;
    __u64 gs;
    __u64 fs;
    __u64 rflags;
} x86_regs;

#define HANDLE_OK(h) ((h) != INVALID_HANDLE_VALUE)

#define PAGE_SIZE 0x1000
#define PAGE_MASK (PAGE_SIZE - 1)
#define PAGE_ALIGN_UP(x) (((__u64)((x)) + PAGE_MASK) & ~PAGE_MASK)
#define PAGE_ALIGN_DOWN(x) ((__u64)((x)) & ~PAGE_MASK)

#define IA32_FS_BASE 0xC0000100ULL
#define IA32_GS_BASE 0xC0000101ULL

#define UC_PROT_R (UC_PROT_READ)
#define UC_PROT_RW (UC_PROT_READ | UC_PROT_WRITE)
#define UC_PROT_RX (UC_PROT_READ | UC_PROT_EXEC)
#define UC_PROT_RWX (UC_PROT_READ | UC_PROT_WRITE | UC_PROT_EXEC)

#define _contain_(a, sz, b)                                                    \
    ((__u64)(a) <= (__u64)(b) && (__u64)(b) < (__u64)(a) + (__u64)(sz))

#define MM_VMAP 2
#define MM_NONE 0
#define MM_HEAP 1

typedef struct {
    void *mem; // the order is important - this one (*mem) needs to be fixed at
               // off 0
    __u8 t;
    __u64 sz;
} mm_t;

typedef struct {
    void *mem;
    __u8 t;
    __u64 sz;
    __u64 off;
} mm_off_t;
#endif
