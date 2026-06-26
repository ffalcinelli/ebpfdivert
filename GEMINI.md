# eBPFDivert Driver

Standalone eBPF driver for packet capture and diversion, designed for high-performance packet interception and WinDivert-compatible filtering on Linux.

## Project Overview

- **Purpose**: Provides a programmable packet diversion layer using Linux eBPF (Traffic Control).
- **Key Technologies**:
    - **eBPF**: Core logic running in the kernel TC (Traffic Control) subsystem.
    - **libbpf**: User-space library for loading and interacting with BPF programs.
    - **CO-RE (Compile Once - Run Everywhere)**: Uses BTF and `vmlinux.h` for portable BPF execution across modern kernels.
- **Architecture**:
    - `src/ebpfdivert.bpf.c`: Kernel-side eBPF code implementing filtering, dropping, sniffing, and diversion logic.
    - `src/ebpfdivert.c`: User-space shared library wrapper (`libebpfdivert.so`) providing a C interface for program/rule loading, packet capture/injection, and telemetry.
    - `src/ebpfdivert-cli.c`: Command-line manager (`ebpfdivert-cli`) for loader, rule configurations, sniffing, and telemetry display.
    - `tests/test_bpf.c`: Mock test suite using `BPF_PROG_TEST_RUN` for rapid kernel-side verification.
    - `tests/test_integration.c`: User-space integration test suite for end-to-end routing validation.
    - **Maps**:
        - `pcap_ringbuf`: High-speed ring buffer for transferring intercepted packets to user-space.
        - `filter_rules` / `filter_rules_ipv6`: Array maps containing matching criteria and action masks.
        - `stats_map`: Per-CPU array for tracking diverted, dropped, sniffed, and parsing/queue/ring buffer error statistics.

## Directory Layout
- `src/`: Kernel-side BPF source and user-space C wrapper/CLI sources.
  - `ebpfdivert.bpf.c`: Core BPF filter code.
  - `ebpfdivert.c`: Library wrapper source.
  - `ebpfdivert-cli.c`: Command line utility source.
- `include/`: Header files, including generated `vmlinux.h` and shared API headers.
- `tests/`: BPF verification tests, user-space integration tests, and automation scripts.
- `build/`: (Local only) Target for object files and binaries.

## Building and Running

### Prerequisites
- Linux Kernel 5.8+ (required for Ring Buffer).
- BTF support enabled in kernel (`CONFIG_DEBUG_INFO_BTF=y`).
- `clang`, `llvm`, `libbpf-dev`.

### Commands
- **Build**: `make`
- **Test BPF (Rapid Mock Verification)**:
  `vagrant up` followed by `vagrant ssh -c "cd /vagrant && make clean && make && sudo ./test_bpf ebpfdivert.bpf.o"`
- **Test Integration (End-to-End)**:
  `vagrant ssh -c "cd /vagrant && sudo ./tests/run_integration_tests.sh"`
- **Clean**: `make clean`

## Development Conventions

- **Coding Style**: Adheres to Linux kernel BPF coding standards.
- **Verification**:
  - All logic changes in `ebpfdivert.bpf.c` must be verified by adding/updating test cases in `tests/test_bpf.c`.
  - API, queueing, routing, and command options must be validated by running/updating integration tests in `tests/test_integration.c`.
- **CI/CD**: GitHub Actions handles automated testing on Ubuntu 24.04 and creates releases for tags.
- **Licensing**: Dual-licensed under **GPLv2** and **LGPLv3**.
