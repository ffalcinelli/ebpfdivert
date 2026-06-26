# Contributing to eBPFDivert

First off, thank you for considering contributing to eBPFDivert! It's people like you that make the open-source community such an amazing place to learn, inspire, and create.

## How Can I Contribute?

### Reporting Bugs
- Use the [GitHub Issue Tracker](https://github.com/ffalcinelli/ebpfdivert/issues) to report bugs.
- Include a clear title, description, and as much relevant information as possible (kernel version, libbpf version, etc.).

### Suggesting Enhancements
- Open an issue with the "enhancement" label.
- Explain why the feature would be useful and how it should work.

### Pull Requests
1. Fork the repository.
2. Create a new branch for your feature or bugfix.
3. Ensure your code follows the existing style (Linux Kernel BPF coding standards).
4. Update the test suite in `tests/test_bpf.c` and/or `tests/test_integration.c` if necessary.
5. Verify your changes using the Vagrant environment:
   ```bash
   vagrant up
   # Run BPF mock tests
   vagrant ssh -c "cd /vagrant && make clean && make && sudo ./test_bpf ebpfdivert.bpf.o"
   # Run integration tests
   vagrant ssh -c "cd /vagrant && sudo ./tests/run_integration_tests.sh"
   ```
6. Submit a PR against the `main` branch.

## Coding Style
- Adhere to the Linux kernel BPF coding standards.
- Use `libbpf` and **CO-RE** (Compile Once – Run Everywhere) best practices.
- Ensure all logic is verified by automated tests.

## Licensing
By contributing to this project, you agree that your contributions will be licensed under the same **Dual GPLv2/LGPLv3** terms as the rest of the project.
