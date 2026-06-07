# eBPFDivert Driver

Standalone eBPF driver for packet capture and diversion, used by [PyDivert](https://github.com/ffalcinelli/pydivert).

## Features
- TC-based packet interception (Ingress/Egress).
- WinDivert-compatible filtering logic.
- Ring buffer for high-performance packet transfer.
- CO-RE (Compile Once - Run Everywhere) support.

## Building
Requires `clang`, `llvm`, and `libbpf-dev`.

```bash
make
```

## Testing
```bash
sudo ./test_bpf ebpfdivert.bpf.o
```

## License
Dual-licensed under LGPL-3.0-or-later and GPL-2.0-or-later.
