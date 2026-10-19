#include "../../include/syp/sype.hh"
#include <assert.h>
#include <windows.h>
extern "C" {
#include "../../include/syp/syscall.h"
};

__attribute__((constructor)) void SlitYerPE::init_wine_syscalls() {
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    assert(HANDLE_OK(ntdll));

    WINE_EACH_SYSCALL(e) {
        assert(!!e && !!e->name); // "Nullptr in Wine-SyscallTable")
        e->fn = (void *)GetProcAddress(ntdll, e->name);

        if (!e->fn)
            DBG_FMT("[!] Failed to GetProcAddress of \"%s\"\n", e->name);
    }
}

__s8 SlitYerPE::wine_name(char *ret, __u64 size, char *dll_name) {
    if (!ret)
        return -1;

    memset(ret, 0, size);
    if (strlen(WIN_SYSTEM32_PATH) + strlen(dll_name) + 1 > size)
        return -1;

    memcpy(ret, WIN_SYSTEM32_PATH, strlen(WIN_SYSTEM32_PATH));
    strcat(ret, dll_name);
    for (__u64 i = 0; i < strlen(ret); i++) {
        ret[i] = tolower(ret[i]);
    }

    assert(strlen(ret) + 1 <= size);

    return 0;
}