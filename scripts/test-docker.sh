#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-or-later OR LGPL-3.0-or-later
# Run the full eBPFDivert build and privileged test suite inside a privileged
# Docker container (uses the host Linux kernel; use scripts/vm.py for 5.15/6.8).
set -euo pipefail

REPO_DIR="$(cd "$(dirname "$0")/.." && pwd)"
IMAGE_NAME="${EBPFDIVERT_TEST_IMAGE:-ebpfdivert-test}"

docker build -t "$IMAGE_NAME" -f "$REPO_DIR/Dockerfile.test" "$REPO_DIR"

exec docker run --rm --privileged --pid=host \
    -v "$REPO_DIR:/src:ro" \
    "$IMAGE_NAME" \
    bash -ceu '
        mountpoint -q /sys/fs/bpf || mount -t bpf bpf /sys/fs/bpf
        mountpoint -q /sys/fs/cgroup || mount -t cgroup2 none /sys/fs/cgroup
        cp -a /src /tmp/work
        cd /tmp/work
        make clean
        make -j"$(nproc)"
        ./test_filter
        ./test_bpf ebpfdivert.bpf.o
        ./tests/run_integration_tests.sh "$@"
    ' -- "$@"
