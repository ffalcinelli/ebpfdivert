# eBPFDivert Driver

Standalone eBPF driver for packet capture and diversion, designed for high-performance packet interception and WinDivert-compatible filtering.

## Project Overview

- **Purpose**: Provides a programmable packet diversion layer using Linux eBPF (Traffic Control).
- **Key Technologies**:
    - **eBPF**: Core logic running in the kernel.
    - **libbpf**: User-space library for loading and interacting with BPF programs.
    - **CO-RE (Compile Once - Run Everywhere)**: Uses `vmlinux.h` for portable BPF execution.
- **Architecture**:
    - `ebpfdivert.bpf.c`: The eBPF kernel-side code implementing packet filtering and diversion logic.
    - `test_bpf.c`: User-space test suite that simulates packet flows using `BPF_PROG_TEST_RUN`.
    - **Maps**:
        - `pcap_ringbuf`: High-speed ring buffer for transferring intercepted packets to user-space.
        - `filter_rules`: Array map containing WinDivert-style filtering rules.
        - `stats_map`: Per-CPU array for tracking diverted, dropped, and sniffed packets.

## Building and Running

### Prerequisites
- `clang` and `llvm` (version 10 or later recommended).
- `libbpf-dev` and kernel headers.

### Commands
- **Build**: Compiles the BPF object and the test utility.
  ```bash
  make
  ```
- **Test**: Runs the automated test suite (requires root for BPF operations).
  ```bash
  sudo ./test_bpf ebpfdivert.bpf.o
  ```
- **Vagrant**: Spin up a pre-configured Ubuntu 22.04 environment for testing.
  ```bash
  vagrant up
  ```
- **Clean**: Removes build artifacts.
  ```bash
  make clean
  ```

## Development Conventions

- **eBPF Coding Style**: Adheres to Linux kernel BPF coding standards.
- **Verification**: All logic changes in `ebpfdivert.bpf.c` should be verified by adding or updating test cases in `test_bpf.c`.
- **CI/CD**: The project uses GitHub Actions for CI (testing on PR/push) and CD (automatic releases on tags). Artifacts are published as GitHub Releases.
- **Packet Buffering**: Uses a fixed-size `pydivert_packet_buffer` (2048 bytes) for packet transfers via the ring buffer.
- **Filtering**: Rules are processed sequentially in the kernel; the `match_mask` determines which fields (IP, Port, Proto, etc.) are checked.
