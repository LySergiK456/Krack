#include <unicorn/unicorn.h>
#include "../../include/syp/dbgserver.hh"
#include "../../include/syp/uc.hh"
#include "../../include/mem.h"

DbgTcp::DbgTcp(std::shared_ptr<SlitYerPE::Razor> _r, __u16 _port) : r{_r}, port{_port} {
	if (!!WSAStartup(MAKEWORD(2, 2), &wsa)) {
		ok=-1;
		return;
	}

	server = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (server == INVALID_SOCKET) {
		ok=-1;
		return;
	}

	addr.sin_family			= AF_INET;
	addr.sin_port 			= htons(port);
	addr.sin_addr.s_addr	= htonl(INADDR_ANY);

	if (bind(server, (sockaddr*)&addr, sizeof(sockaddr_in)) == SOCKET_ERROR) {
		ok=-1;
		return;
	}
}

DbgTcp::~DbgTcp() {
	closesocket(server);
	WSACleanup();
}

int DbgTcp::Run() {
	if (listen(server, SOMAXCONN) == SOCKET_ERROR)
		return (ok=-1);

	while (1) {
		sockaddr_in c_addr{};
		int c_addr_len = sizeof(sockaddr_in);

		SOCKET client = accept(server, (sockaddr*)&c_addr, &c_addr_len);
		if (client == INVALID_SOCKET) {
			continue;
		}

		dbg_header hdr{};
		hdr.regs.rax	= Uc::reg(r->ldr.uc, X86Reg::rax);
		hdr.regs.rbx	= Uc::reg(r->ldr.uc, X86Reg::rbx);
		hdr.regs.rcx	= Uc::reg(r->ldr.uc, X86Reg::rcx);
		hdr.regs.rdx	= Uc::reg(r->ldr.uc, X86Reg::rdx);
		hdr.regs.rdi	= Uc::reg(r->ldr.uc, X86Reg::rdi);
		hdr.regs.rsi	= Uc::reg(r->ldr.uc, X86Reg::rsi);
		hdr.regs.rsp	= Uc::reg(r->ldr.uc, X86Reg::rsp);
		hdr.regs.rbp	= Uc::reg(r->ldr.uc, X86Reg::rbp);
		hdr.regs.r8		= Uc::reg(r->ldr.uc, X86Reg::r8);
		hdr.regs.r9		= Uc::reg(r->ldr.uc, X86Reg::r9);
		hdr.regs.r10	= Uc::reg(r->ldr.uc, X86Reg::r10);
		hdr.regs.r11	= Uc::reg(r->ldr.uc, X86Reg::r11);
		hdr.regs.r12	= Uc::reg(r->ldr.uc, X86Reg::r12);
		hdr.regs.r13	= Uc::reg(r->ldr.uc, X86Reg::r13);
		hdr.regs.r14	= Uc::reg(r->ldr.uc, X86Reg::r14);
		hdr.regs.r15	= Uc::reg(r->ldr.uc, X86Reg::r15);
		hdr.regs.rip	= Uc::reg(r->ldr.uc, X86Reg::rip);
		// hdr.regs.gs		= Uc::reg(r->ldr.uc, X86Reg::gs);
		// hdr.regs.fs		= Uc::reg(r->ldr.uc, X86Reg::fs);
		hdr.regs.rflags	= 0;//Uc::reg(r->ldr.uc, X86Reg::rflags);

		char buf[0x21000]{};
		__u64 off = 0;
		memcpy(buf, (char*)&hdr, sizeof(dbg_header));
		off += sizeof(dbg_header);

		uc_mem_region	*regs;
		__u32 *n_maps = &(reinterpret_cast<dbg_header*>(buf))->num_of_maps;;
		uc_mem_regions(r->ldr.uc, &regs, n_maps);
		for (__u32 i=0; i<*n_maps; i++) {
			dbg_memmap mm{
				.begin=regs[i].begin, .end=regs[i].end, .perm=regs[i].perms
			};
			for (auto& m : r->ldr.pmem_maps) {
				if (m->addr == mm.begin && !!m->name)
					strncpy((char*)&mm.name, m->name, 0x100-sizeof(BYTE));
			}
			memcpy(buf+off, (char*)&mm, sizeof(dbg_memmap));
			off += sizeof(dbg_memmap);
		}

		int n = send(client, buf, off, 0);
		if (!n || n == SOCKET_ERROR || n < sizeof(dbg_header)) {
			puts("FUCK!");
			continue;
		} else {
			puts("SEND");
		}

		// char buf[0x1000];
		// while (1) {
		// 	int n1 = static_cast<__u32>(recv(client, buf, sizeof(buf), 0));
		// 	if (!n1 || n1<0) {
		// 		closesocket(client);
		// 	}
		// }
		closesocket(client);
	}
}