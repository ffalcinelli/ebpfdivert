# eBPFDivert

[![CI](https://github.com/ffalcinelli/ebpfdivert/actions/workflows/ci.yml/badge.svg)](https://github.com/ffalcinelli/ebpfdivert/actions/workflows/ci.yml)
[![License: GPL v2](https://img.shields.io/badge/License-GPL%20v2-blue.svg)](LICENSE)
[![License: LGPL v3](https://img.shields.io/badge/License-LGPL%20v3-blue.svg)](LICENSE)

**eBPFDivert** is a high-performance eBPF-based packet diversion engine for Linux. It provides a programmable packet interception layer compatible with the **Divert** ecosystem, bringing WinDivert-style filtering logic to Linux Traffic Control (TC).

## Overview

In the Windows world, [WinDivert](https://github.com/basil00/WinDivert) is the standard for user-space packet interception. **eBPFDivert** aims to provide a similar experience on Linux by leveraging the power of eBPF (Extended Berkeley Packet Filter).

### Key Features
- **TC-based Interception**: Hook into both Ingress and Egress traffic using the Traffic Control (TC) subsystem.
- **Zero-Copy Transfers**: High-speed BPF Ring Buffer for efficient, low-overhead packet streaming from kernel to user-space.
- **WinDivert-Compatible Logic**: Fully customizable IPv4/IPv6 filtering rules supporting ports, protocols (TCP, UDP, ICMP, ICMPv6), direction, loopback, TTL, and TCP flags.
- **Logical Inversion**: Match fields selectively using invert masks (e.g., matching any port *except* port 80).
- **User-Space Queueing**: Built-in queueing mechanism in the client layer to handle burst packet arrivals and avoid packet drops under backpressure.
- **Standalone CLI Manager**: Control loading/unloading, live packet sniffing (with PCAP generation), rules configuration, and real-time statistics.
- **C Shared Library API**: Simple and clean C wrapper (`libebpfdivert.so`) designed to easily integrate with external languages (Python, Java, Go, etc.).
- **CO-RE (Compile Once – Run Everywhere)**: Built with `libbpf` and BTF support for portability across modern Linux kernel versions without recompilation.
- **Dual Licensing**: Fully compatible with the existing WinDivert/Divert ecosystem (GPLv2/LGPLv3).

## Architecture

The engine consists of:
1. **Kernel-side (eBPF)**: An eBPF classifier program (`src/ebpfdivert.bpf.c`) that filters packets at the TC layer, applying action rules (`divert`, `drop`, `sniff`) and sending packets to user-space via a ring buffer.
2. **C Wrapper Library (`libebpfdivert.so`)**: Manages interaction with BPF maps, simplifies rules creation, and provides thread-safe or queued packet capture and reinjection.
3. **CLI Utility (`ebpfdivert-cli`)**: A lightweight manager implementing all library actions for scripting and standalone usage.

### BPF Maps
- `pcap_ringbuf`: A `BPF_MAP_TYPE_RINGBUF` used to stream intercepted packets to user-space.
- `filter_rules` / `filter_rules_ipv6`: Array maps (`BPF_MAP_TYPE_ARRAY`) containing the packet matching criteria and action masks.
- `stats_map`: A per-CPU array for tracking metrics (Diverted, Dropped, Sniffed, Parsing Errors, Ringbuf Full, Queue Full).

## Project Structure
- `src/`:
  - `ebpfdivert.bpf.c`: Kernel-side BPF program.
  - `ebpfdivert.c`: Library wrapper source code (`libebpfdivert.so`).
  - `ebpfdivert-cli.c`: Standalone loader and rules manager CLI.
- `include/`:
  - `ebpfdivert.h`: User-space C library API.
  - `ebpfdivert_shared.h`: Shared structures, constants, and rule definitions.
  - `vmlinux.h`: BPF-kernel types helper.
- `tests/`:
  - `test_bpf.c`: Mock verifications using `BPF_PROG_TEST_RUN`.
  - `test_integration.c`: Integration test suite for loopback, veth namespaces, and burst queueing.
  - `run_integration_tests.sh`: Automation script to execute all integration tests.
- `Makefile`: Build instructions.
- `Vagrantfile`: Pre-configured Ubuntu 24.04 environment for rapid test runs.

## Getting Started

### Prerequisites
- **Kernel**: Version 5.8+ (for Ring Buffer support) with BTF enabled.
- **Tools**: `clang`, `llvm`, `libbpf-dev`, `make`, `gcc`, `ethtool` (for integration tests).

### Preferred: Using Vagrant
The easiest way to develop and test is using the provided Vagrant environment:

```bash
# Start the VM (Ubuntu 24.04)
vagrant up

# Build all targets and run mock BPF tests
vagrant ssh -c "cd /vagrant && make clean && make && sudo ./test_bpf ebpfdivert.bpf.o"

# Run end-to-end integration tests
vagrant ssh -c "cd /vagrant && sudo ./tests/run_integration_tests.sh"
```

### Manual Build
```bash
make
# Run mock tests
sudo ./test_bpf ebpfdivert.bpf.o
# Run integration tests
sudo ./tests/run_integration_tests.sh
```

## CLI Usage

The `ebpfdivert-cli` executable provides command-line control of the driver and rules.

```bash
Usage: ebpfdivert-cli <command> [args]

Commands:
  load [interface] [priority] [bpf_object_path]  Attach driver (defaults to 'all' interfaces, priority 0)
  unload [interface]                             Detach driver (defaults to 'all' interfaces)
  stats                                          Print packet telemetry stats
  sniff [pcap_file]                              Sniff captured packets (Ctrl+C to stop, outputs to console or PCAP)
  rules list                                     List all active rules
  rules clear                                    Clear all active rules
  rules add <idx> <proto> <dst_ip/mask> <dst_port_range> <action>
                                                 Add a basic rule (idx 0-63)
                                                 proto: tcp, udp, icmp, icmpv6, any
                                                 dst_ip/mask: e.g., 192.168.1.0/24, any
                                                 dst_port_range: e.g., 80, 8000-8010, type/code, any
                                                 action: divert, drop, sniff
  rules add-ext <idx> <action> [opts]            Add advanced rule with options
```

### Advanced Rule (add-ext) Options
- `--proto <proto>`: `tcp`, `udp`, `icmp`, `icmpv6`, `any`
- `--src-ip <ip/mask>`: Source IP and CIDR mask (e.g. `10.0.0.0/8`, `any`)
- `--dst-ip <ip/mask>`: Destination IP and CIDR mask (e.g. `192.168.1.1/32`, `any`)
- `--src-port <port_range>`: Source port or range (e.g. `80`, `1000-2000`)
- `--dst-port <port_range>`: Destination port/range or ICMP type/code (e.g. `443`, `8/0` for ICMP Echo Request)
- `--direction <dir>`: `ingress`, `egress`, `any`
- `--loopback <lo>`: `yes`, `no`, `any`
- `--ttl <ttl>`: Time to Live limit (0-255)
- `--tcp-flags <flags>`: Match TCP flags (e.g. `SYN`, `ACK`, `RST`, `FIN`, or raw hex `0x02`)
- `--tcp-flags-mask <mask>`: Mask specifying which TCP flags to verify
- `--invert <fields>`: Comma-separated fields to logically invert (e.g. `src-ip`, `dst-port`, `proto`)

*Example:*
```bash
# Drop all outgoing TCP connection attempts (SYN) to port 80/443 on eth0
sudo ./ebpfdivert-cli rules add-ext 0 drop --proto tcp --dst-port 80-443 --direction egress --tcp-flags SYN --tcp-flags-mask SYN
```

## C API Overview

`libebpfdivert` exposes a high-level API declared in [ebpfdivert.h](include/ebpfdivert.h):

### Driver Management
- `int ebpfdivert_load(const char *ifname, const char *obj_path, uint32_t priority);`
- `int ebpfdivert_unload(const char *ifname);`

### Rule Management
- `int ebpfdivert_rules_clear(void);`
- `int ebpfdivert_rules_list(void);`
- `int ebpfdivert_rules_add(int idx, const char *proto, const char *ip_cidr, const char *port_range, const char *action);`
- `int ebpfdivert_rules_add_extended(int idx, const struct ebpfdivert_rule_opt *opt);`

### Data Flow & Queueing
- `ebpfdivert_handle_t *ebpfdivert_open(uint32_t priority);` - Opens a handle to receive/send packets. Handles are not thread-safe.
- `int ebpfdivert_recv(ebpfdivert_handle_t *h, struct divert_packet_buffer *buf, size_t buf_len, int timeout_ms);` - Captures packets. Incorporates a queue to safely cache back-to-back packets.
- `int ebpfdivert_send(ebpfdivert_handle_t *h, const struct divert_packet_buffer *buf);` - Inject/reinject packet back to interface.
- `int ebpfdivert_set_max_queue_size(ebpfdivert_handle_t *h, int size);` - Configure size of the packet backpressure queue.
- `void ebpfdivert_close(ebpfdivert_handle_t *h);`

### Telemetry
- `int ebpfdivert_get_stats(uint64_t *stats, int stats_len);` - Retrieve packet counts (diverted, dropped, sniffed, errors, full buffers).

## Packet Format

Packets read using `ebpfdivert_recv` are wrapped in a `divert_packet_buffer` structure:

```c
struct divert_pkt_header {
    uint32_t pkt_len;   // Total length of the packet
    uint32_t ifindex;   // Network interface index where packet was captured
    uint16_t direction; // 1 for Ingress, 2 for Egress
    uint16_t l2_len;    // Length of the Layer 2 (e.g. Ethernet) header
    uint32_t cap_len;   // Captured length (respects snaplen)
};

struct divert_packet_buffer {
    struct divert_pkt_header header;
    uint8_t data[2048]; // Packet payload
};
```

## Contributing
Contributions are welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## License
Dual-licensed under **GPLv2** and **LGPLv3**. See [LICENSE](LICENSE) for details.
