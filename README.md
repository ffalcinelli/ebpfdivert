# eBPFDivert

[![CI](https://github.com/ffalcinelli/ebpfdivert/actions/workflows/ci.yml/badge.svg)](https://github.com/ffalcinelli/ebpfdivert/actions/workflows/ci.yml)
[![License: GPL v2](https://img.shields.io/badge/License-GPL%20v2-blue.svg)](LICENSE)
[![License: LGPL v3](https://img.shields.io/badge/License-LGPL%20v3-blue.svg)](LICENSE)

**eBPFDivert** is the Linux counterpart of [WinDivert](https://github.com/basil00/WinDivert): it captures,
filters, modifies, drops and re-injects network packets from user space, and reports socket, flow and handle
events, using eBPF. `libebpfdivert.so` exposes a **WinDivert-compatible C API**: the same layers, flags,
parameters, filter language and 80-byte `WINDIVERT_ADDRESS` layout. It is the Linux backend of
[pydivert](https://github.com/ffalcinelli/pydivert) and [jdivert](https://github.com/ffalcinelli/jdivert).

## Features

- **All WinDivert layers**:
  - `NETWORK` and `NETWORK_FORWARD`, through TC hooks on every interface or a selected set.
  - `SOCKET`: bind, connect, listen, accept and close, with the process ID. Bind and connect can be refused.
  - `FLOW`: TCP and UDP flows established and deleted.
  - `REFLECT`: divert handles opened and closed by any process.
- **The WinDivert filter language itself.** The compiler and evaluator are WinDivert's own code, vendored
  unmodified. Filters are lowered to eBPF rules that run in the kernel. When a filter is too rich for the
  kernel rules, the kernel captures a superset: user space evaluates the exact filter and re-injects
  whatever does not match, so the application sees exactly what WinDivert would give it.
- **WinDivert semantics**:
  - Priorities chain handles.
  - Re-injected packets are only seen by lower-priority handles, flagged *impostor*.
  - Loopback traffic is reported once, as outbound.
  - Inbound IP fragments need the `FRAGMENTS` flag.
  - `SNIFF`, `DROP`, `RECV_ONLY` and `SEND_ONLY` behave as on Windows.
  - `QUEUE_LENGTH`, `QUEUE_TIME` and `QUEUE_SIZE` are supported, and so is `WinDivertShutdown`.
- **Offloads stay on.** GSO/GRO/TSO packets of up to 64 KB are captured whole and re-injected, and the kernel
  re-segments them.
- **Crash safety.** If a process dies without closing its handles, its programs stop diverting within
  3 seconds. Event layers use `bpf_link`s, which go away with the process. Leftover TC filters are removed
  by the next open, by `ebpfdivert_unregister()`, or by `ebpfdivert-cli cleanup`.
- **Self-contained library.** The BPF objects are embedded, and libbpf, libelf, zstd and zlib are linked in.
  Release builds need only glibc 2.28 or later, on amd64 and arm64.

## Requirements

- Linux **5.10+** with BTF (`/sys/kernel/btf/vmlinux`) and cgroup v2 (for the event layers).
- Root, or `CAP_BPF` + `CAP_NET_ADMIN` (+ `CAP_NET_RAW` for re-injection).
- To build: `clang`, `llvm`, `gcc`, `make`, `libelf-dev`, `zlib1g-dev`. libbpf comes from the
  `third_party/libbpf` submodule (`git submodule update --init`); if it is missing, the system libbpf is used.

## Quick start

```c
#include <ebpfdivert/ebpfdivert.h>

uint8_t pkt[EBPFDIVERT_MTU_MAX];
struct ebpfdivert_address addr;
uint32_t len;
ebpfdivert_handle_t *h = ebpfdivert_open("tcp.DstPort == 80 or tcp.SrcPort == 80",
                                         EBPFDIVERT_LAYER_NETWORK, 0, 0, NULL);
while (ebpfdivert_recv(h, pkt, sizeof(pkt), &len, &addr, -1) == 0) {
    /* inspect or modify pkt; clear addr.*_checksum flags after changes */
    ebpfdivert_send(h, pkt, len, NULL, &addr);
}
ebpfdivert_close(h);
```

`ebpfdivert-cli sniff "udp.DstPort == 53" dns.pcap` does the same from the command line, writing a pcap file.

## Building and testing

```bash
git submodule update --init
make                      # libebpfdivert.so, ebpfdivert-cli, BPF objects, tests
make check                # filter conformance + fuzzing, no root needed
sudo ./test_bpf           # every WinDivert filter vector through the real BPF program (BPF_PROG_TEST_RUN)
sudo ./tests/run_integration_tests.sh   # namespaces/veth: divert, inject, GSO, forward, events, crashes
```

Privileged tests are meant to run in the Vagrant VMs. `default` is Ubuntu 24.04 (kernel 6.8), and `legacy`
is Ubuntu 22.04 (kernel 5.15):

```bash
vagrant up default && vagrant ssh default -c "cd /vagrant && make clean && make && ./test_filter && \
    sudo ./test_bpf && sudo ./tests/run_integration_tests.sh"
vagrant destroy -f default
```

Release artifacts come from `scripts/build_release.sh`, run inside a `manylinux_2_28` container. The
WinDivert sources are re-vendored with `scripts/sync_windivert.sh`.

## Documentation

- [Architecture](docs/architecture.md): hooks, filter pipeline, injection paths, priorities, event layers.
- [C API reference](docs/api_reference.md)
- [Rules reference](docs/rules_reference.md): kernel rule tables and the pinned CLI mode.

## License

Dual-licensed under **GPL-2.0-or-later** and **LGPL-3.0-or-later**. The vendored WinDivert sources
(`src/wd/`) carry the same dual license.
