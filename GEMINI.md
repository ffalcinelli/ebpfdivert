# eBPFDivert Driver

Standalone eBPF driver for packet capture and diversion, designed for high-performance packet interception and WinDivert-compatible filtering on Linux.

## Project Overview

- **Purpose**: Provides a programmable packet diversion layer using Linux eBPF (Traffic Control).
- **Key Technologies**:
    - **eBPF**: Core logic running in the kernel TC (Traffic Control) subsystem.
    - **libbpf**: User-space library for loading and interacting with BPF programs.
    - **CO-RE (Compile Once - Run Everywhere)**: Uses BTF and `vmlinux.h` for portable BPF execution across modern kernels.
- **Architecture**:
    - `src/ebpfdivert.bpf.c`: Kernel-side code implementing filtering, dropping, sniffing, and diversion logic.
    - `tests/test_bpf.c`: User-space test suite using `BPF_PROG_TEST_RUN` for rapid validation.
    - **Maps**:
        - `pcap_ringbuf`: High-speed ring buffer for transferring intercepted packets to user-space.
        - `filter_rules`: Array map containing matching criteria and action masks.
        - `stats_map`: Per-CPU array for tracking diverted, dropped, and sniffed packets.

## Directory Layout
- `src/`: Kernel-side BPF source code.
- `include/`: Header files, including generated `vmlinux.h`.
- `tests/`: User-space verification suite.
- `build/`: (Local only) Target for object files and binaries.

## Building and Running

### Prerequisites
- Linux Kernel 5.8+ (required for Ring Buffer).
- BTF support enabled in kernel (`CONFIG_DEBUG_INFO_BTF=y`).
- `clang`, `llvm`, `libbpf-dev`.

### Commands
- **Build**: `make`
- **Test (Preferred)**: `vagrant up` followed by `vagrant ssh -c "cd /vagrant && make clean && make && sudo ./test_bpf ebpfdivert.bpf.o"`
- **Clean**: `make clean`

## Development Conventions

- **Coding Style**: Adheres to Linux kernel BPF coding standards.
- **Verification**: All logic changes in `ebpfdivert.bpf.c` must be verified by adding/updating test cases in `tests/test_bpf.c`.
- **CI/CD**: GitHub Actions handles automated testing on Ubuntu 24.04 and creates releases for tags.
- **Licensing**: Dual-licensed under **GPLv2** and **LGPLv3**.
