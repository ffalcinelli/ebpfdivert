# eBPFDivert

eBPFDivert is the Linux counterpart of WinDivert. `libebpfdivert.so` exposes a WinDivert-compatible C API on
top of eBPF: the same layers, flags, parameters, filter language and 80-byte `WINDIVERT_ADDRESS`. It is the
Linux backend of pydivert and jdivert, which download its pinned releases. Any change to observable semantics
must match what WinDivert does on Windows.

## Requirements

- Linux 5.10+ with BTF (`/sys/kernel/btf/vmlinux`), and cgroup v2 for the SOCKET/FLOW layers.
- Build deps: `clang`, `llvm`, `gcc`, `make`, `pkg-config`, `libelf-dev`, `zlib1g-dev`.
- libbpf comes from the `third_party/libbpf` submodule (`git submodule update --init`). If the submodule is
  missing, the system libbpf is used.
- Running needs root, or `CAP_BPF` + `CAP_NET_ADMIN` (+ `CAP_NET_RAW` for injection).

## Commands

```bash
make -j"$(nproc)"                          # libebpfdivert.so, ebpfdivert-cli, BPF objects, test binaries (-Werror)
make check                                 # ./test_filter: filter-lowering conformance + fuzzing; no root
sudo ./test_bpf ebpfdivert.bpf.o           # WinDivert filter vectors through the real BPF program (BPF_PROG_TEST_RUN)
sudo ./tests/run_integration_tests.sh      # netns/veth topology, then ./test_integration
sudo ./tests/run_integration_tests.sh gso  # only cases whose name contains "gso"
make check-version                         # EBPFDIVERT_VERSION vs. git tag
sudo ./ebpfdivert-cli cleanup              # remove TC filters left by killed processes
```

Run privileged tests in the Vagrant VMs, not on the host. `default` is Ubuntu 24.04 (kernel 6.8); `legacy` is
Ubuntu 22.04 (kernel 5.15) and covers older verifiers:

```bash
vagrant up default && vagrant ssh default -c "cd /vagrant && make clean && make && ./test_filter && \
    sudo ./test_bpf && sudo ./tests/run_integration_tests.sh"
vagrant destroy -f default
```

CI (`.github/workflows/ci.yml`) runs the same build and tests on amd64 and arm64 runners. Release `.so` files
come from `scripts/build_release.sh`, inside a `manylinux_2_28` container with `STATIC_DEPS=1`. Only glibc 2.28+
is a runtime dependency; libbpf, libelf, zstd and zlib are linked in.

## Architecture

Full detail is in `docs/architecture.md`. The C API is in `docs/api_reference.md`; kernel rule tables and the CLI
are in `docs/rules_reference.md`.

- **Filter pipeline:**
  - **Compile.** WinDivert's own compiler (`src/wd/`) turns the filter string into a decision DAG.
  - **Lower.** `src/prefilter.c` lowers the DAG to ≤64 conjunctive kernel rules per address family. Fields it
    cannot express are *widened* (dropped from the rule), so the rules always match a superset.
  - **Evaluate exactly.** If anything was widened, or the packet is a fragment, `src/handle.c` runs the exact
    WinDivert evaluator in user space and silently re-injects packets that don't match.
- **Network layers** (`src/ebpfdivert.bpf.c`):
  - **Attach.** cls_bpf on the `clsact` qdisc of each interface plus `lo`. Do not switch to TCX: it maps
    `TC_ACT_STOLEN` to "next".
  - **Capture.** Whole skbs, including 64 KB GSO/GRO aggregates, go to `pcap_ringbuf`. Matching rules live in
    `filter_rules` / `filter_rules_ipv6` and the LPM tries; counters are in `stats_map`. Per-rule matching uses
    global BPF functions, to stay within older verifiers' complexity limits.
- **Injection** (`ebpfdivert_send`):
  - **Path.** Raw IP or `AF_PACKET` (+ `virtio_net_hdr` for GSO), chosen by direction and loopback. Inbound
    packets go out on `lo` and are `bpf_redirect`ed to the target interface.
  - **Capture context.** The L2 header and GSO size are stored in the unused part of the address union, so
    callers must hand back all 80 bytes unchanged.
- **Priorities.** WinDivert priority `p` maps to TC priority `30001 - p`. Re-injected skbs carry
  `mark = 0x4D490000 | tc_prio`. A handle skips marked packets whose priority is at or above its own; handles
  below it see them as impostors.
- **Event layers** (`src/ebpfdivert_events.bpf.c`): SOCKET and FLOW attach cgroup v2 and sockops programs via
  `bpf_link`. REFLECT has no BPF program; it diffs the handle registry.
- **Registry and crash safety:**
  - **Registry.** Handles are recorded in the pinned map `/sys/fs/bpf/ebpfdivert/registry`, under
    `flock(/run/ebpfdivert.lock)`.
  - **Heartbeat.** A 500 ms heartbeat thread keeps the programs active. After 3 s without it, they pass all
    traffic.
  - **Reaping.** Dead owners' TC filters are removed on the next open.
- **Embedding.** The BPF objects are embedded into the `.so` by `src/bpf_embed.S`. The exported ABI is
  `src/libebpfdivert.map`.

## Rules

- **Never edit the vendored WinDivert files in `src/wd/`** (`windivert*.h`, `windivert_*.c`). Porting code
  belongs in `src/wd/compat/windows.h` and `src/wd/wd_port.c`. Re-vendor with
  `scripts/sync_windivert.sh [../windivert]`, which also regenerates `tests/wd_vectors.c`.
- Every behavior change needs a test in the matching suite:

  | Change | Test file |
  | --- | --- |
  | Kernel program (`*.bpf.c`) | `tests/test_bpf.c` |
  | Filter lowering (`prefilter.c`) | `tests/test_filter.c` |
  | API, queueing, injection, routing or CLI | `tests/test_integration.c` |
- New public symbols must be added to `src/libebpfdivert.map` and `include/ebpfdivert.h`.
- BPF code follows Linux kernel BPF style and libbpf CO-RE practice (`include/vmlinux.h`). Keep the old
  verifiers in mind and test on `legacy`.
- On release, bump `EBPFDIVERT_VERSION` in `include/ebpfdivert.h` to match the tag, then update the pins in
  pydivert (`pyproject.toml`) and jdivert (`pom.xml`).
- GitHub Actions must be pinned to full commit SHAs with a `# vX.Y.Z` comment. CI verifies this with
  `ffalcinelli/pinner` (`.pinner.toml`).
- New files get the SPDX header `GPL-2.0-or-later OR LGPL-3.0-or-later`.
