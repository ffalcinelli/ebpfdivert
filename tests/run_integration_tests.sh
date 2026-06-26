#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-or-later OR LGPL-3.0-or-later
set -e

if [ "$EUID" -ne 0 ]; then
  echo "ERROR: Please run this script as root (sudo)."
  exit 1
fi

VETH0="veth_test0"
VETH1="veth_test1"
NS="ns1"

cleanup() {
  echo "Cleaning up interfaces and namespace..."
  ip link delete "$VETH0" 2>/dev/null || true
  ip netns delete "$NS" 2>/dev/null || true
  if [ -x ./ebpfdivert-cli ]; then
    ./ebpfdivert-cli unload "$VETH0" 2>/dev/null || true
    ./ebpfdivert-cli unload lo 2>/dev/null || true
  fi
  rm -f /tmp/veth_rx.txt
}
trap cleanup EXIT

echo "Setting up virtual ethernet pair and network namespace..."
ip link delete "$VETH0" 2>/dev/null || true
ip netns delete "$NS" 2>/dev/null || true

ip netns add "$NS"
ip link add "$VETH0" type veth peer name "$VETH1"
ip link set "$VETH1" netns "$NS"

echo "Configuring IP addresses..."
ip addr add 10.200.1.1/24 dev "$VETH0"
ip netns exec "$NS" ip addr add 10.200.1.2/24 dev "$VETH1"

echo "Bringing interfaces up..."
ip link set "$VETH0" up
ip netns exec "$NS" ip link set "$VETH1" up
ip netns exec "$NS" ip link set lo up

echo "Disabling TX/RX checksum offloading..."
ethtool -K "$VETH0" tx off rx off 2>/dev/null || true
ip netns exec "$NS" ethtool -K "$VETH1" tx off rx off 2>/dev/null || true

sleep 0.5

if [ ! -f ./test_integration ]; then
  make
fi

echo "Starting integration tests..."
./test_integration lo "$VETH0"

echo "Integration tests finished!"
