# eBPFDivert Driver

Standalone eBPF driver for packet capture and diversion, used by [PyDivert](https://github.com/ffalcinelli/pydivert).

## Project Structure
- `src/`: Kernel-side eBPF source code.
- `include/`: Shared header files (e.g., `vmlinux.h`).
- `tests/`: User-space test suite.
- `Makefile`: Build configuration.
- `Vagrantfile`: Pre-configured testing environment.

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

### Preferred: Using Vagrant
The provided `Vagrantfile` sets up a controlled environment with all necessary dependencies. This is the recommended way to run tests with the required elevated privileges.

```bash
vagrant up
vagrant ssh -c "cd /vagrant && make clean && make && sudo ./test_bpf ebpfdivert.bpf.o"
```

The project is built automatically during the initial `vagrant up`.

### Local Testing
If you have the dependencies (`clang`, `llvm`, `libbpf-dev`) installed locally:

```bash
make
sudo ./test_bpf ebpfdivert.bpf.o
```

## CI/CD
This project uses GitHub Actions for Continuous Integration and automated releases.
- **CI**: Every push to `main` or pull request triggers a build and test suite on Ubuntu 22.04.
- **Releases**: Pushing a tag (e.g., `v1.0.0`) automatically creates a GitHub Release and attaches the compiled `ebpfdivert.bpf.o` artifact.

## License
Dual-licensed under LGPL-3.0-or-later and GPL-2.0-or-later.
