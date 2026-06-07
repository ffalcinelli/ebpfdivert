CLANG ?= clang
CFLAGS ?= -O2 -g
LIBBPF_LIBS ?= -lbpf

BPF_OBJ = ebpfdivert.bpf.o
BPF_SRC = ebpfdivert.bpf.c

all: $(BPF_OBJ) test_bpf

$(BPF_OBJ): $(BPF_SRC) vmlinux.h
	$(CLANG) $(CFLAGS) -target bpf -c $< -o $@

test_bpf: test_bpf.c
	gcc $(CFLAGS) $< $(LIBBPF_LIBS) -o $@

clean:
	rm -f $(BPF_OBJ) test_bpf
