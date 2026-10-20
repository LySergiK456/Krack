#include "../include/utils.hh"
#include <windows.h>

void Util::Red() {
    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    if (!HANDLE_OK(h))
        return;

    SetConsoleTextAttribute(h, FOREGROUND_RED | FOREGROUND_INTENSITY);
}
void Util::Green() {
    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    if (!HANDLE_OK(h))
        return;

    SetConsoleTextAttribute(h, FOREGROUND_GREEN | FOREGROUND_INTENSITY);
}
void Util::Blue() {
    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    if (!HANDLE_OK(h))
        return;

    SetConsoleTextAttribute(h, FOREGROUND_BLUE | FOREGROUND_INTENSITY);
}
void Util::White() {
    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    if (!HANDLE_OK(h))
        return;

    SetConsoleTextAttribute(h, FOREGROUND_RED | FOREGROUND_GREEN |
                                   FOREGROUND_BLUE | FOREGROUND_INTENSITY);
}

void Util::Reset() {
    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    if (!HANDLE_OK(h))
        return;

    SetConsoleTextAttribute(h, FOREGROUND_RED | FOREGROUND_GREEN |
                                   FOREGROUND_BLUE);
}

__u64 Util::hash(char *name) {
    return (__u64)std::hash<std::string>{}(name);
};