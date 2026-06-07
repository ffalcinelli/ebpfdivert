# eBPFDivert

[![CI](https://github.com/ffalcinelli/ebpfdivert/actions/workflows/ci.yml/badge.svg)](https://github.com/ffalcinelli/ebpfdivert/actions/workflows/ci.yml)
[![License: GPL v2](https://img.shields.io/badge/License-GPL%20v2-blue.svg)](LICENSE)
[![License: LGPL v3](https://img.shields.io/badge/License-LGPL%20v3-blue.svg)](LICENSE)

**eBPFDivert** is a high-performance eBPF-based packet diversion engine for Linux. It provides a programmable packet interception layer compatible with the **Divert** ecosystem, bringing WinDivert-style filtering logic to Linux Traffic Control (TC).

## Overview

In the Windows world, [WinDivert](https://github.com/basil00/WinDivert) is the standard for user-space packet interception. **eBPFDivert** aims to provide a similar experience on Linux by leveraging the power of eBPF (Extended Berkeley Packet Filter).

### Key Features
- **TC-based Interception**: Hook into both Ingress and Egress traffic using the Traffic Control (TC) subsystem.
- **Zero-Copy Transfers**: Uses high-speed eBPF Ring Buffers for efficient packet transfer from kernel to user-space.
- **WinDivert-compatible Logic**: Implements filtering masks and logic familiar to WinDivert/Divert users.
- **CO-RE (Compile Once – Run Everywhere)**: Built with `libbpf` and BTF support for portability across different Linux distributions.
- **Dual Licensing**: Fully compatible with the existing Divert ecosystem (GPLv2/LGPLv3).

## Architecture

The engine consists of two main components:
1. **Kernel-side (eBPF)**: A classifier program that intercepts packets at the TC layer, applies filtering rules, and optionally diverts them to a ring buffer.
2. **User-space (Loader/Tests)**: Interacts with the kernel via eBPF Maps and consumes diverted packets from the Ring Buffer.

### BPF Maps
- `pcap_ringbuf`: A `BPF_MAP_TYPE_RINGBUF` used to stream intercepted packets to user-space.
- `filter_rules`: A `BPF_MAP_TYPE_ARRAY` containing matching criteria (IPs, Ports, Protocols).
- `stats_map`: A per-CPU array for tracking performance metrics (packets diverted, dropped, or sniffed).

## Project Structure
- `src/`: Kernel-side eBPF source code (`ebpfdivert.bpf.c`).
- `include/`: Shared header files, including `vmlinux.h`.
- `tests/`: User-space test suite and simulation scripts.
- `Makefile`: Build configuration.
- `Vagrantfile`: Pre-configured Ubuntu 24.04 environment for local development.

## Getting Started

### Prerequisites
- **Kernel**: Version 5.8+ (for Ring Buffer support) with BTF enabled.
- **Tools**: `clang`, `llvm`, `libbpf-dev`, `make`, `gcc`.

### Preferred: Using Vagrant
The easiest way to develop and test is using the provided Vagrant environment:

```bash
# Start the VM (Ubuntu 24.04)
vagrant up

# Build and run tests inside the VM
vagrant ssh -c "cd /vagrant && make clean && make && sudo ./test_bpf ebpfdivert.bpf.o"
```

### Manual Build
```bash
make
sudo ./test_bpf ebpfdivert.bpf.o
```

## Usage

While `eBPFDivert` is primarily designed as a backend for [PyDivert](https://github.com/ffalcinelli/pydivert) and [JDivert](https://github.com/ffalcinelli/jdivert), it can be used independently. 

Packets transferred via the ring buffer are prefixed with a `divert_pkt_header`:

```c
struct divert_pkt_header {
    uint32_t pkt_len;   // Total length of the packet
    uint32_t ifindex;   // Network interface index
    uint16_t direction; // 1 for Ingress, 2 for Egress
    uint16_t l2_len;    // Length of the L2 header (e.g. Ethernet)
    uint32_t pad;       // Alignment padding
};
```

## Contributing
Contributions are welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## License
Dual-licensed under **GPLv2** and **LGPLv3**. See [LICENSE](LICENSE) for details.
