#include "../include/pe64/pe64.hh"
extern "C" {
#include "../include/types.h"
};

int main() {
    auto pe = std::make_shared<PE64_IMAGE>(
        new PE64_IMAGE("/home/rax/win10_dll/ntdll.dll"));

    return 0;
}