CLANG ?= clang
CFLAGS ?= -O2 -g -Wall -Wextra
LIBBPF_LIBS ?= -lbpf
INCLUDES := -Iinclude -Isrc

BPF_OBJ = ebpfdivert.bpf.o
BPF_SRC = src/ebpfdivert.bpf.c
TEST_EXE = test_bpf
TEST_SRC = tests/test_bpf.c
CLI_EXE = ebpfdivert-cli
CLI_SRC = src/ebpfdivert-cli.c
LIB_SO = libebpfdivert.so
LIB_SRC = src/ebpfdivert.c
TEST_INT_EXE = test_integration
TEST_INT_SRC = tests/test_integration.c

all: $(BPF_OBJ) $(TEST_EXE) $(LIB_SO) $(CLI_EXE) $(TEST_INT_EXE)

$(BPF_OBJ): $(BPF_SRC) include/vmlinux.h
	$(CLANG) $(CFLAGS) -target bpf $(INCLUDES) -c $< -o $@

$(TEST_EXE): $(TEST_SRC)
	gcc $(CFLAGS) $(INCLUDES) $< $(LIBBPF_LIBS) -o $@

$(LIB_SO): $(LIB_SRC)
	gcc $(CFLAGS) $(INCLUDES) -fPIC -shared $< $(LIBBPF_LIBS) -o $@

$(CLI_EXE): $(CLI_SRC) $(LIB_SO)
	gcc $(CFLAGS) $(INCLUDES) $< -L. -lebpfdivert -Wl,-rpath,. -o $@

$(TEST_INT_EXE): $(TEST_INT_SRC) $(LIB_SO)
	gcc $(CFLAGS) $(INCLUDES) $< -L. -lebpfdivert -Wl,-rpath,. -o $@

clean:
	rm -f $(BPF_OBJ) $(TEST_EXE) $(LIB_SO) $(CLI_EXE) $(TEST_INT_EXE)

PREFIX ?= /usr/local
INSTALL ?= install

.PHONY: all clean install uninstall check-version

check-version:
	./scripts/check_version.sh


install: all
	$(INSTALL) -d $(DESTDIR)$(PREFIX)/bin
	$(INSTALL) -d $(DESTDIR)$(PREFIX)/lib
	$(INSTALL) -d $(DESTDIR)$(PREFIX)/include/ebpfdivert
	$(INSTALL) -m 0755 $(CLI_EXE) $(DESTDIR)$(PREFIX)/bin/
	$(INSTALL) -m 0755 $(LIB_SO) $(DESTDIR)$(PREFIX)/lib/
	$(INSTALL) -m 0644 include/ebpfdivert.h $(DESTDIR)$(PREFIX)/include/ebpfdivert/
	$(INSTALL) -m 0644 include/ebpfdivert_shared.h $(DESTDIR)$(PREFIX)/include/ebpfdivert/
	$(INSTALL) -d $(DESTDIR)$(PREFIX)/lib/ebpfdivert
	$(INSTALL) -m 0644 $(BPF_OBJ) $(DESTDIR)$(PREFIX)/lib/ebpfdivert/

uninstall:
	rm -f $(DESTDIR)$(PREFIX)/bin/$(CLI_EXE)
	rm -f $(DESTDIR)$(PREFIX)/lib/$(LIB_SO)
	rm -rf $(DESTDIR)$(PREFIX)/include/ebpfdivert
	rm -rf $(DESTDIR)$(PREFIX)/lib/ebpfdivert


