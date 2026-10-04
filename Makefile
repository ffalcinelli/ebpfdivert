CLANG ?= clang
CC ?= gcc
CFLAGS ?= -O2 -g -Wall -Wextra -Werror
INCLUDES := -Iinclude -Isrc -Isrc/wd
WD_INCLUDES := -Isrc/wd/compat $(INCLUDES)
BUILD := build

# libbpf: link the pinned submodule statically when it is checked out
# (release builds), otherwise the system library.
LIBBPF_SRC := third_party/libbpf/src
ifneq ($(wildcard $(LIBBPF_SRC)/Makefile),)
LIBBPF_A := $(BUILD)/libbpf/libbpf.a
LIBBPF_INC := -I$(BUILD)/libbpf/include
ifeq ($(STATIC_DEPS),1)
# Release builds (scripts/build_release.sh): libelf, zstd and zlib linked in
# too, so libebpfdivert.so only depends on glibc.
EBD_STATIC_LIBS ?= $(shell pkg-config --static --libs-only-l libelf zlib)
LIBBPF_LIBS := $(LIBBPF_A) -Wl,-Bstatic $(EBD_STATIC_LIBS) -Wl,-Bdynamic
else
LIBBPF_LIBS := $(LIBBPF_A) -lelf -lz
endif
else
LIBBPF_A :=
LIBBPF_INC :=
LIBBPF_LIBS ?= -lbpf
endif

BPF_OBJ = ebpfdivert.bpf.o
BPF_SRC = src/ebpfdivert.bpf.c
EVENTS_OBJ = ebpfdivert_events.bpf.o
EVENTS_SRC = src/ebpfdivert_events.bpf.c
LIB_SO = libebpfdivert.so
LIB_SONAME = libebpfdivert.so.0
CLI_EXE = ebpfdivert-cli
TEST_EXE = test_bpf
TEST_INT_EXE = test_integration
TEST_FILTER_EXE = test_filter

LIB_OBJS = $(BUILD)/ebpfdivert.o $(BUILD)/handle.o $(BUILD)/prefilter.o \
           $(BUILD)/wd_port.o $(BUILD)/bpf_embed.o
# Objects shared with the unprivileged filter test (no libbpf needed).
FILTER_OBJS = $(BUILD)/prefilter.o $(BUILD)/wd_port.o

HEADERS = include/ebpfdivert.h include/ebpfdivert_shared.h src/internal.h \
          src/prefilter.h src/wd/wd.h

all: $(BPF_OBJ) $(EVENTS_OBJ) $(LIB_SO) $(CLI_EXE) $(TEST_EXE) $(TEST_INT_EXE) $(TEST_FILTER_EXE)

$(BUILD):
	mkdir -p $(BUILD)

$(BUILD)/libbpf/libbpf.a: | $(BUILD)
	$(MAKE) -C $(LIBBPF_SRC) BUILD_STATIC_ONLY=1 OBJDIR=$(abspath $(BUILD)/libbpf/obj) \
		DESTDIR=$(abspath $(BUILD)/libbpf) PREFIX= LIBDIR=/ INCLUDEDIR=/include \
		EXTRA_CFLAGS="-fPIC -O2 $(LIBBPF_EXTRA_CFLAGS)" install
	cp $(BUILD)/libbpf/libbpf.a $@ 2>/dev/null || true

$(BPF_OBJ): $(BPF_SRC) include/vmlinux.h include/ebpfdivert_shared.h $(LIBBPF_A)
	$(CLANG) $(CFLAGS) -target bpf $(LIBBPF_INC) $(INCLUDES) -c $< -o $@

# The WinDivert sources are written for MSVC and type-pun freely (e.g. the
# checksum pseudo-headers): they must not be compiled with strict aliasing.
$(EVENTS_OBJ): $(EVENTS_SRC) include/vmlinux.h include/ebpfdivert_shared.h $(LIBBPF_A)
	$(CLANG) $(CFLAGS) -target bpf $(LIBBPF_INC) $(INCLUDES) -c $< -o $@

$(BUILD)/wd_port.o: src/wd/wd_port.c src/wd/*.h src/wd/*.c src/wd/compat/windows.h | $(BUILD)
	$(CC) $(CFLAGS) -fno-strict-aliasing -fPIC $(WD_INCLUDES) -c $< -o $@

$(BUILD)/prefilter.o: src/prefilter.c $(HEADERS) src/wd/compat/windows.h | $(BUILD)
	$(CC) $(CFLAGS) -fPIC $(WD_INCLUDES) -c $< -o $@

$(BUILD)/%.o: src/%.c $(HEADERS) $(LIBBPF_A) | $(BUILD)
	$(CC) $(CFLAGS) -fPIC $(LIBBPF_INC) $(INCLUDES) -c $< -o $@

$(BUILD)/bpf_embed.o: src/bpf_embed.S $(BPF_OBJ) $(EVENTS_OBJ) | $(BUILD)
	$(CC) -c -DEBPFDIVERT_BPF_OBJ='"$(BPF_OBJ)"' -DEBPFDIVERT_EVENTS_OBJ='"$(EVENTS_OBJ)"' $< -o $@

$(LIB_SO): $(LIB_OBJS) src/libebpfdivert.map
	$(CC) $(CFLAGS) $(LDFLAGS) -shared -Wl,-soname,$(LIB_SONAME) -Wl,--version-script=src/libebpfdivert.map \
		-Wl,-z,noexecstack $(LIB_OBJS) $(LIBBPF_LIBS) -lpthread -o $@
	ln -sf $(LIB_SO) $(LIB_SONAME)

$(CLI_EXE): src/ebpfdivert-cli.c $(LIB_SO)
	$(CC) $(CFLAGS) $(INCLUDES) $< -L. -lebpfdivert -Wl,-rpath,'$$ORIGIN' -o $@

$(TEST_EXE): tests/test_bpf.c $(FILTER_OBJS) $(BPF_OBJ)
	$(CC) $(CFLAGS) $(LDFLAGS) $(LIBBPF_INC) $(INCLUDES) -Itests $< $(FILTER_OBJS) $(LIBBPF_LIBS) -o $@

$(TEST_INT_EXE): tests/test_integration.c $(LIB_SO)
	$(CC) $(CFLAGS) $(INCLUDES) $< -L. -lebpfdivert -lpthread -Wl,-rpath,'$$ORIGIN' -o $@

$(TEST_FILTER_EXE): tests/test_filter.c tests/wd_vectors.c $(FILTER_OBJS)
	$(CC) $(CFLAGS) $(INCLUDES) -Itests $< $(FILTER_OBJS) -o $@

# Unprivileged checks (no root, no BPF): filter conformance + fuzzing.
check: $(TEST_FILTER_EXE)
	./$(TEST_FILTER_EXE)

clean:
	rm -rf $(BUILD) $(BPF_OBJ) $(EVENTS_OBJ) $(LIB_SO) $(LIB_SONAME) $(CLI_EXE) $(TEST_EXE) $(TEST_INT_EXE) $(TEST_FILTER_EXE)

PREFIX ?= /usr/local
INSTALL ?= install

.PHONY: all clean install uninstall check check-version

check-version:
	./scripts/check_version.sh

install: all
	$(INSTALL) -d $(DESTDIR)$(PREFIX)/bin
	$(INSTALL) -d $(DESTDIR)$(PREFIX)/lib
	$(INSTALL) -d $(DESTDIR)$(PREFIX)/include/ebpfdivert
	$(INSTALL) -m 0755 $(CLI_EXE) $(DESTDIR)$(PREFIX)/bin/
	$(INSTALL) -m 0755 $(LIB_SO) $(DESTDIR)$(PREFIX)/lib/
	ln -sf $(LIB_SO) $(DESTDIR)$(PREFIX)/lib/$(LIB_SONAME)
	$(INSTALL) -m 0644 include/ebpfdivert.h $(DESTDIR)$(PREFIX)/include/ebpfdivert/
	$(INSTALL) -m 0644 include/ebpfdivert_shared.h $(DESTDIR)$(PREFIX)/include/ebpfdivert/
	$(INSTALL) -d $(DESTDIR)$(PREFIX)/lib/ebpfdivert
	$(INSTALL) -m 0644 $(BPF_OBJ) $(EVENTS_OBJ) $(DESTDIR)$(PREFIX)/lib/ebpfdivert/

uninstall:
	rm -f $(DESTDIR)$(PREFIX)/bin/$(CLI_EXE)
	rm -f $(DESTDIR)$(PREFIX)/lib/$(LIB_SO) $(DESTDIR)$(PREFIX)/lib/$(LIB_SONAME)
	rm -rf $(DESTDIR)$(PREFIX)/include/ebpfdivert
	rm -rf $(DESTDIR)$(PREFIX)/lib/ebpfdivert
