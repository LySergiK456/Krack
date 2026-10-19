#include "../types.h"

#ifndef KRACK_SYSCALL_H
#define KRACK_SYSCALL_H
#define U64_PTR(rax)                                                           \
    struct {                                                                   \
        __u64 rax;                                                             \
        void *rax##_ptr;                                                       \
        void *rax##_ptr_size;                                                  \
        __u64 rax##_v;                                                         \
    }

typedef struct {
    U64_PTR(rax);
    U64_PTR(r10);
    U64_PTR(rdx);
    U64_PTR(r8);
    U64_PTR(r9);
    U64_PTR(rsp_h28);
    U64_PTR(rsp_h30);
    U64_PTR(rsp_h38);
    U64_PTR(rsp_h40);
} __NtArgs;

#define NT_ARGS_EACH(args, ptr, p_sz, reg, val)                                \
    for (__u64 i = 0; i < sizeof(__NtArgs);                                    \
         i += sizeof(__u64) * 2 + sizeof(void *) * 2)                          \
        for (__u64 reg = *(__u64 *)(&(((char *)(args))[i])),                   \
                   *ptr = (__u64 *)(&(((char *)(args))[i + 0x8])),             \
                   *p_sz = (__u64 *)(&(((char *)(args))[i + 0x10])),           \
                   *val = (__u64 *)(&(((char *)(args))[i + 0x18]));            \
             !!ptr; ptr = NULL)

typedef struct {
    void *fn;
    char *name;
    __u32 v;
} NtSyscallTableEntry;

#define WIN10_SYSCALL_COUNT 945
#define WINE_SYSCALL_COUNT 470

extern NtSyscallTableEntry wine_syscalls[];
extern NtSyscallTableEntry win10_syscalls[];

#define WINE_EACH_SYSCALL(e)                                                   \
    for (NtSyscallTableEntry *e = &wine_syscalls[0];                           \
         e < &wine_syscalls[WINE_SYSCALL_COUNT]; e++)

#define WIN10_EACH_SYSCALL(e)                                                  \
    for (NtSyscallTableEntry *e = &win10_syscalls[0];                          \
         e < &win10_syscalls[WIN10_SYSCALL_COUNT]; e++)

#endif
