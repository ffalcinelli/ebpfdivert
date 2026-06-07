# Security Policy

## Supported Versions

Currently, the following versions of eBPFDivert are supported with security updates:

| Version | Status |
| ------- | --------------------- |
| main    | ✅ Supported |

## Reporting a Vulnerability

If you discover a potential security vulnerability in eBPFDivert, please do **not** open a public issue. Instead, report it privately to the maintainers:

- Fabio Falcinelli: [fabio.falcinelli@gmail.com](mailto:fabio.falcinelli@gmail.com)

We aim to acknowledge receipt of your report as soon as possible. Please note that while we take security seriously, this is a community-maintained project and we cannot guarantee a specific resolution timeframe or response window. We will provide updates as we investigate the issue and work toward a fix.

### eBPF and Kernel Safety

eBPFDivert interacts with the Linux kernel via eBPF. If you discover a vulnerability in the eBPF subsystem itself (e.g. verifier bypass or kernel panic caused by a bug in the BPF JIT/verifier), please report it to the [Linux kernel security team](https://www.kernel.org/doc/html/latest/process/security-bugs.html).

## What to Include in a Report

To help us address the issue quickly, please include:
- A clear description of the vulnerability.
- A minimal reproducible example (PoC) if possible.
- Any potential impact or exploitation scenarios.

## Security Best Practices for eBPFDivert Users

eBPFDivert operates at a low level in the network stack and requires `CAP_NET_ADMIN` and `CAP_BPF` (or root) privileges. To ensure your system remains secure:

1. **Principle of Least Privilege**: Only run the necessary components with elevated privileges.
2. **Filter Validation**: Ensure that any user-provided input used to generate filter rules is strictly validated before being loaded into the BPF maps.
3. **Keep libbpf Updated**: Ensure you are using a recent version of `libbpf` to benefit from the latest security and stability improvements.

## Disclosure Policy

We follow a responsible disclosure policy:
1. Acknowledge the report.
2. Investigate and confirm the vulnerability.
3. Work on a fix.
4. Release a new version with the fix.
5. Publicly disclose the vulnerability after a fix is available and users have had time to update.
