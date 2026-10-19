// #define WIN32_LEAN_AND_MEAN
// #include <winsock2.h>
// #include <ws2tcpip.h>
// #include <windows.h>
// #include <memory>

// #ifndef KRACK_DEBUG_SERVER_HH
// #define KRACK_DEBUG_SERVER_HH
// #include "./sype.hh"
// #include "../conf.hh"

// // make strtab
// typedef struct {
// 	char		filename[0x100];
// 	x86_regs	regs;
// 	__u32		num_of_maps;
// } dbg_header;

// typedef struct {
// 	char	name[0x100];
// 	__u64	begin;
// 	__u64	end;
// 	__u32	perm;
// } dbg_memmap;

// class DbgTcp {
// 	WSADATA				wsa;
// 	SOCKET				server;
// 	sockaddr_in			addr{};
// 	__u16				port{};
// 	__s8				ok{0};
// 	std::shared_ptr<SlitYerPE::Razor> r;

// public:
// 	DbgTcp(std::shared_ptr<SlitYerPE::Razor> _r, __u16 port);
// 	~DbgTcp();
// 	int Run();
// };
// #endif
