CLANG ?= clang
CFLAGS ?= -O2 -g
LIBBPF_LIBS ?= -lbpf
INCLUDES := -Iinclude -Isrc

BPF_OBJ = ebpfdivert.bpf.o
BPF_SRC = src/ebpfdivert.bpf.c
TEST_EXE = test_bpf
TEST_SRC = tests/test_bpf.c
CLI_EXE = ebpfdivert-cli
CLI_SRC = src/ebpfdivert-cli.c

all: $(BPF_OBJ) $(TEST_EXE) $(CLI_EXE)

$(BPF_OBJ): $(BPF_SRC) include/vmlinux.h
	$(CLANG) $(CFLAGS) -target bpf $(INCLUDES) -c $< -o $@

$(TEST_EXE): $(TEST_SRC)
	gcc $(CFLAGS) $(INCLUDES) $< $(LIBBPF_LIBS) -o $@

$(CLI_EXE): $(CLI_SRC)
	gcc $(CFLAGS) $(INCLUDES) $< $(LIBBPF_LIBS) -o $@

clean:
	rm -f $(BPF_OBJ) $(TEST_EXE) $(CLI_EXE)
