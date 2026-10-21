#ifndef KRACK_UTILS_HH
#define KRACK_UTILS_HH
#include <stdio.h>
#include <assert.h>
#include <string>
#include <fstream>
#include <functional>
#include <memory>
extern "C" {
#include "./types.h"
#include "./mem.h"
};

#define Generic(T) template <typename T>

Generic(T) struct lambda_traits;
template <typename C, typename Ret, typename Arg, typename... Args>
struct lambda_traits<Ret (C::*)(Arg, Args...) const> {
    using first = Arg;
};
Generic(Fn) using lambda_arg =
    typename lambda_traits<decltype(&Fn::operator())>::first;

template <typename Fn> auto defer(Fn fn) {
    return std::shared_ptr<void>(
        nullptr, std::bind([fn = std::move(fn)](void) mutable { fn(); }));
};

#define __cafe_cat1_(a, b) a##b
#define __cafe_cat__(a, b) __cafe_cat1_(a, b)

#define _defer(fn) auto __cafe_cat__(__defer_, __COUNTER__) = defer(fn)

namespace Util {
struct outfile_t {
    std::ofstream out;

    template <typename S>
    outfile_t(S *file)
        : out(reinterpret_cast<char *>(file),
              std::ios::out | std::ios::binary) {}
    ~outfile_t() {
        _defer([&] { out.close(); }); // It's neat
    }

    template <typename T> void pwrite(T *ptr, __u64 size, __u64 off) {
        out.seekp(off, std::ios::beg);
        out.write(reinterpret_cast<char *>(ptr), size);
    }

    __u64 pos() { return static_cast<__u64>(out.tellp()); }
    bool ok() { return (!!out && out.good()); }
};
}; // namespace Util

namespace Util {
template <typename E> struct MMap_t {
    union {
        void *mem;
        E *e;
    };
    __u32 count;
    __u64 sz;
    __s8 ok{};

  private:
    __u32 ndx{0};

  public:
    struct iterator {
        E *ptr;

        E &operator*() const { return *ptr; }
        iterator &operator++() {
            ptr++;
            return *this;
        }
        bool operator!=(const iterator &i) const { return ptr != i.ptr; };
    };
    MMap_t(__u32 n=0x4000)
        : count{n}, sz{PAGE_ALIGN_UP(count * sizeof(E))}
    {
        mem = alloc(sz);
        if (!mem && (ok = -1))
            return;
    }

    E &push(E &new_e) {
        if (ndx == count) {
            __u64 new_sz = PAGE_ALIGN_UP((count + 0x4000) * sizeof(E));
            void *new_mem = alloc(new_sz);
            assert(!!new_mem);

            CopyMemory(new_mem, mem, sz);
            VirtualFree(mem, 0, MEM_RELEASE);
            mem = new_mem;
            e = static_cast<E *>(mem);
            sz = new_sz;
            count += 0x4000;
        }
        return (e[ndx++] = std::move(new_e));
    }

    __u64 size() { return ndx + 1; }

    iterator begin() { return {e}; }
    iterator end() { return {&e[count]}; }

  private:
    void *alloc(__u64 size) {
        void *dat =
            VirtualAlloc(NULL, size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
        if (!!dat)
            ZeroMemory(dat, size);
        return dat;
    }
};

__u64 hash(char *);
};

namespace Util {
void Red();
void Green();
void Blue();
void Purple();
void White();
void Reset();
}; // namespace Util
#endif
