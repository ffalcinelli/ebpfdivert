#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-or-later OR LGPL-3.0-or-later
#
# Build the test topology and run ./test_integration.  Offloads (TSO, GSO,
# GRO) are deliberately left ON: large aggregated skbs must survive
# divert + re-injection.
#
#   ns1: veth_test1 10.200.1.2 fd00:1::2  <->  root: veth_test0 10.200.1.1 fd00:1::1
#   ns2: veth_test3 10.200.2.2            <->  root: veth_test2 10.200.2.1
set -e

if [ "$EUID" -ne 0 ]; then
  echo "ERROR: Please run this script as root (sudo)."
  exit 1
fi

cd "$(dirname "$0")/.."

FWD_V4=$(cat /proc/sys/net/ipv4/ip_forward)

cleanup() {
  echo "Cleaning up interfaces and namespaces..."
  ip link delete veth_test0 2>/dev/null || true
  ip link delete veth_test2 2>/dev/null || true
  ip netns delete ns1 2>/dev/null || true
  ip netns delete ns2 2>/dev/null || true
  echo "$FWD_V4" > /proc/sys/net/ipv4/ip_forward
  ./ebpfdivert-cli cleanup 2>/dev/null || true
}
trap cleanup EXIT
cleanup >/dev/null 2>&1 || true

echo "Setting up namespaces..."
ip netns add ns1
ip netns add ns2
ip link add veth_test0 type veth peer name veth_test1
ip link add veth_test2 type veth peer name veth_test3
ip link set veth_test1 netns ns1
ip link set veth_test3 netns ns2

ip addr add 10.200.1.1/24 dev veth_test0
ip addr add fd00:1::1/64 dev veth_test0 nodad
ip addr add 10.200.2.1/24 dev veth_test2
ip netns exec ns1 ip addr add 10.200.1.2/24 dev veth_test1
ip netns exec ns1 ip addr add fd00:1::2/64 dev veth_test1 nodad
ip netns exec ns2 ip addr add 10.200.2.2/24 dev veth_test3

for dev in veth_test0 veth_test2; do ip link set "$dev" up; done
ip netns exec ns1 ip link set veth_test1 up
ip netns exec ns1 ip link set lo up
ip netns exec ns2 ip link set veth_test3 up
ip netns exec ns2 ip link set lo up
ip netns exec ns1 ip route add 10.200.2.0/24 via 10.200.1.1
ip netns exec ns2 ip route add 10.200.1.0/24 via 10.200.2.1
echo 1 > /proc/sys/net/ipv4/ip_forward

# Make sure aggregation is actually exercised.
ethtool -K veth_test0 gro on tso on gso on 2>/dev/null || true
ip netns exec ns1 ethtool -K veth_test1 gro on tso on gso on 2>/dev/null || true

sleep 0.5

if [ ! -x ./test_integration ]; then
  make
fi

echo "Starting integration tests..."
./test_integration "$@"
echo "Integration tests finished!"
