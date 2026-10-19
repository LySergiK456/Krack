BDIR = ./build
GCC = ccache x86_64-w64-mingw32-gcc
GXX = ccache x86_64-w64-mingw32-g++

UC_CFLAGS =	-I/home/rax/Documents/unicorn/include
X86_CFLAGS=	-I./x86disass/include

UC_LDFLAGS =-L/home/rax/Documents/unicorn/build-win64
X86_LDFLAGS=-L./x86disass/build

objs = wine_tabl.o win10_tabl.o main.o dex.o razor.o ldr.o ldr_mem.o ldr_image.o ldr_env.o sype.o uc.o dbgserver.o pe64.o util.o utils.o #llist.o pe64_c_api.o rel_yayo.o rel_1dlsd.o xtc.o extc.o
test_rel_objs = test_rel.o rel_1dlsd.o pe64.o util.o utils.o llist.o pe64_c_api.o rel_yayo.o pe64_c_api.o xtc.o extc.o
test_pe64_objs = test_pe64.o pe64.o pe64.o util.o utils.o pe64_c_api.o pe64_c_api.o


CXXFLAGS = -g -MMD -MP
# CFLAGS = -w -lws2_32 $(UC_CFLAGS) $(X86_CFLAGS)
CFLAGS = -w -g -MMD -MP
# CFLAGS = -w

-include $(objs:%=$(BDIR)/%.d)


MAKE = make
ECHO = echo
MKDIR= mkdir

TARGET = ./specimen/b.exe

main.o razor.o ldr.o ldr_mem.o ldr_image.o ldr_env.o util.o uc.o sype.o: CFLAGS += $(UC_CFLAGS) -lunicorn
test_rel.o rel_yayo.o rel_1dlsd.o dex.o: CFLAGS += $(X86_CFLAGS) -lx86disass $(UC_CFLAGS) -lunicorn

all: make_it
	@$(MAKE) run

.PHONY: make_it
make_it: make_builddir $(objs)
	@echo "[+] Compiling with -lunicorn -lx86disass"
	$(GXX) $(addprefix $(BDIR)/,$(objs)) $(X86_LDFLAGS) -lx86disass $(UC_LDFLAGS) -lunicorn $(CXXFLAGS) -o a.exe
	@echo "-----------------------------"
	@echo ""

test_rel: make_builddir $(test_rel_objs)
	@echo "[+] Test(Rel) with -lunicorn -lx86disass"
	@$(GXX) $(BDIR)/*.o $(X86_LDFLAGS) -lx86disass $(UC_LDFLAGS) -lunicorn $(CXXFLAGS)  -o a.exe
	@echo "-----------------------------"
	@echo ""

test_pe64: make_builddir $(test_pe64_objs)
	@echo [+] Compiling
	@$(GXX) $(BDIR)/*.o $(CFLAGS) $(CXXFLAGS)  -o a.exe
	@echo "-----------------------------"
	@echo ""

.PHONY: run
run:
	@echo "[+] Running " $(TARGET)
	WINEPATH=. time wine ./a.exe $(TARGET)

clean:
	rm -rf $(BDIR)/*

make_builddir:
	@if [ ! -d "$(BDIR)" ]; then				\
		$(ECHO) "-----------------------------";\
		$(ECHO) "Making build dir " "$(BDIR)";	\
		$(MKDIR) $(BDIR);						\
		$(ECHO) "-----------------------------";\
	fi

###
# To build Object files
#
%.o: src/%.c
	$(GCC) -c $< -o $(BDIR)/$@ $(CFLAGS)

%.o: src/%.cc
	$(GXX) -c $< -o $(BDIR)/$@ $(CFLAGS) $(CXXFLAGS)

%.o: src/ldr/%.cc
	$(GXX) -c $< -o $(BDIR)/$@ $(CFLAGS) $(CXXFLAGS)

%.o: src/syscall_tabl/%.c
	$(GCC) -c $< -o $(BDIR)/$@ $(CFLAGS)

%.o: tests/%.cc
	$(GXX) -c $< -o $(BDIR)/$@ $(CFLAGS) $(CXXFLAGS)

%.o: src/rel_insn/%.cc
	$(GXX) -c $< -o $(BDIR)/$@ $(CFLAGS) $(CXXFLAGS)

%.o: src/rel_insn/%.c
	$(GCC) -c $< -o $(BDIR)/$@ $(CFLAGS)

%.o: src/xtc/%.cc
	$(GXX) -c $< -o $(BDIR)/$@ $(CFLAGS) $(CXXFLAGS)

%.o: src/xtc/%.c
	$(GCC) -c $< -o $(BDIR)/$@ $(CFLAGS)

%.o: src/syp/%.cc
	$(GXX) -c $< -o $(BDIR)/$@ $(CFLAGS) $(CXXFLAGS)

%.o: ./%.cc
	$(GXX) -c $< -o $(BDIR)/$@ $(CFLAGS) $(CXXFLAGS)

