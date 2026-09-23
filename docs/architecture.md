# eBPFDivert architecture

eBPFDivert implements the WinDivert model on Linux. A **handle** is opened with a WinDivert filter, a layer, a
priority and flags. It receives the matching packets or events with a `WINDIVERT_ADDRESS`, and it can
re-inject packets, modified or not. Each handle loads its own instance of the BPF program, so handles never
share maps or rules.

```
                   user space                                    kernel
 ┌───────────────────────────────────────┐      ┌───────────────────────────────────────────┐
 │ ebpfdivert_open(filter, layer, ...)   │      │ TC ingress/egress (cls_bpf, per iface)    │
 │   WinDivert compiler (src/wd)         │ rules│   parse → match rules → STOLEN/SHOT/pass  │
 │   lowering (prefilter.c) ─────────────┼─────▶│   copy whole skb to ring buffer           │
 │ ebpfdivert_recv()                     │ ring │                                           │
 │   ring → exact filter eval ◀──────────┼──────│ cgroup/sockops programs (event layers)    │
 │   ├ match: queue (WinDivert limits)   │      │                                           │
 │   └ no match: re-inject               │      │                                           │
 │ ebpfdivert_send()                     │      │                                           │
 │   AF_PACKET (+vnet GSO) / raw IP ─────┼─────▶│ marked skb: skipped by the injector and   │
 └───────────────────────────────────────┘      │ higher priorities                         │
                                                └───────────────────────────────────────────┘
```

## 1. Filters

1. **Compilation.** The filter string is compiled by WinDivert's own compiler (`src/wd/windivert_helper.c`,
   built unmodified by `src/wd/wd_port.c`). Syntax, errors and error positions are exactly those of
   `WinDivertHelperCompileFilter`.
2. **Lowering** (`src/prefilter.c`). The compiled decision DAG is turned into at most 64 conjunctive kernel
   rules per address family (`struct filter_rule`/`filter_rule_ipv6`). Each ACCEPT path becomes one or more
   rules.
   - These fields are lowered exactly: protocol, addresses (CIDR-shaped ranges), port ranges, ICMP
     type/code, TTL/hop limit, TCP flags, direction, loopback, and local/remote fields (split by direction).
   - Anything else is *widened*, i.e. dropped from the rule, which keeps the rules a superset.
3. **Exact evaluation.** If anything was widened, or the packet is a fragment, user space runs WinDivert's
   evaluator (`WinDivertExecuteFilter`) on each captured packet:
   - A non-matching packet is re-injected, as if the handle had never seen it. When sniffing, it is simply
     discarded.
   - For `DROP` handles, matching packets are dropped in user space.
   - Exactly lowered filters are handled entirely in the kernel.

`tests/test_filter.c` runs WinDivert's filter test vectors plus randomized differential fuzzing. It checks that
the lowering is always a superset, and equal to the filter whenever it is flagged exact. `tests/test_bpf.c` runs
the same vectors through the real BPF program.

## 2. Network layers (`src/ebpfdivert.bpf.c`)

The programs are attached as cls_bpf filters on the `clsact` qdisc of every selected interface, plus `lo`.
TCX links are deliberately not used, because TCX maps `TC_ACT_STOLEN` to "next". Their only alternative,
dropping, makes TCP back off on every diverted segment.

- **Capture.** The whole skb (GSO/GRO aggregates up to 64 KB) is copied to the ring buffer, using three
  record size classes (2 KB, 16 KB, 64 KB). The divert verdict is `TC_ACT_STOLEN`, sniff passes the packet,
  and drop is `TC_ACT_SHOT`. When the ring is full, packets pass (fail open).
- **Loopback.** Loopback packets cross `lo` twice (egress, then ingress). Only egress is reported, as
  outbound with `Loopback` set, like WinDivert.
- **NETWORK vs NETWORK_FORWARD.**
  - A forwarded packet is one leaving an interface with `skb->ingress_ifindex != 0`.
  - When IP forwarding is enabled, ingress packets are also checked with `bpf_fib_lookup` so that NETWORK
    only sees locally delivered traffic.
- **Fragments.** Inbound fragments are only captured with `FRAGMENTS`. Rules cannot judge fragments, so
  they always go to user space for exact evaluation.
- **Non-IP traffic** (ARP, LLDP, ...) is never captured.
- **Per-rule matching** runs in global BPF functions. Each is verified once, which keeps the 64-rule loops
  within the complexity limit of older kernels.

### Injection (`ebpfdivert_send`)

The address decides the path.

| Packet | Path |
| --- | --- |
| Loopback | Raw IP socket (`IPPROTO_RAW`): regular local output, so 127/8 and `::1` are not dropped as martians. |
| Outbound (or forward) with its captured context | `AF_PACKET` on the capture interface, reusing the saved L2 header. |
| Outbound without context (built by the user) | Raw IP socket: routed like any packet. |
| Inbound | `AF_PACKET` on `lo` with `REDIRECT_MARK_MASK \| ifindex`: the `lo` ingress hook `bpf_redirect()`s it to the target's ingress. |

- **Captured context.** The L2 header and GSO size of a received packet are stored in the unused part of the
  address union. Bindings must keep the 80 bytes intact between recv and send.
- **Large packets.** Packets larger than the MTU are sent with `PACKET_VNET_HDR` and a `virtio_net_hdr`
  describing TCP/UDP segmentation, so the kernel re-segments them.
- **Checksums.** Clearing the `IPChecksum`/`TCPChecksum`/`UDPChecksum` flags asks for recalculation, as with
  WinDivert. Captured packets often carry offloaded (partial) checksums, so their flags are 0.

### Priorities and loop prevention

- **TC priority.** WinDivert priority `p` maps to TC priority `30001 - p`. Priority 0 means "after every
  existing handle": the next free TC priority from the registry (see §4).
- **Loop prevention.** Re-injected packets carry `skb->mark = 0x4D490000 | tc_priority`. A handle skips a
  marked packet when its own TC priority is lower than or equal to the mark's. Lower-priority handles see it
  with `Impostor` set.
- **Inbound redirects.** Inbound injections go through `lo` with `SO_PRIORITY = 0x4D4B0000 | tc_priority`.
  The redirect clears `skb->priority`, so the `lo` hook moves the priority into the mark first
  (`REDIRECTED_MARK`).

## 3. Event layers (`src/ebpfdivert_events.bpf.c`)

The event programs attach to the cgroup v2 root through `bpf_link`s. Each event is delivered as a zero-length
packet with the WinDivert Flow/Socket union: endpoint (socket cookie), process ID, local/remote address and
port, and protocol.

| Layer | Events | Programs |
| --- | --- | --- |
| SOCKET | BIND, CONNECT, LISTEN, ACCEPT, CLOSE | `cgroup/post_bind4/6`, `cgroup/connect4/6`, `sockops` (listen, passive established), `cgroup/sock_release` |
| FLOW | ESTABLISHED, DELETED | `sockops` (established, state → CLOSE) for TCP; `cgroup_skb` first packet of a 5-tuple for UDP (DELETED when the socket is released) |

- **Process ID.** It is taken from the current task, or from socket-local storage filled at `sock_create` (and
  cloned to accepted sockets).
- **SOCKET blocking.** Without `SNIFF`, a SOCKET handle refuses matching BIND and CONNECT events, and the
  process gets `EPERM`. The decision is taken in the kernel, so the filter must lower exactly to event rules
  (event, protocol, local/remote address and port, process ID). LISTEN and ACCEPT cannot be refused on Linux:
  such filters fail with `EOPNOTSUPP` unless `SNIFF` is set.
- **WinDivert quirk.** As in WinDivert, the `ip`/`ipv6` fields are always false on the FLOW and SOCKET layers.

**REFLECT** has no BPF program. It diffs the handle registry (§4) every 100 ms and reports OPEN/CLOSE events
with the handle's process, layer, flags and priority. The packet data is the serialized filter object
(`@WinDiv_...`), as on Windows.

## 4. Registry, heartbeat and cleanup

- **Registry.** Every handle is recorded in a pinned hash map, `/sys/fs/bpf/ebpfdivert/registry`, updated
  under `flock(/run/ebpfdivert.lock)`. Each entry holds the PID and its start time, the TC priority, the
  attachments and the filter.
- **Reaping.** Entries of dead processes are reaped, and their TC filters detached, on every open, by
  `ebpfdivert_unregister()` and by `ebpfdivert-cli cleanup`.
- **Heartbeat.** A library thread refreshes each handle's heartbeat every 500 ms. The BPF programs let
  everything through once it is more than 3 s old (`STAT_OWNER_GONE`), so a killed process never keeps
  diverting or dropping traffic.

## 5. Receive queue and parameters

The ring buffer is drained into a user-space queue bounded by `QUEUE_LENGTH` (packets) and `QUEUE_SIZE`
(bytes). Entries older than `QUEUE_TIME` are dropped when dequeued, and drops are counted in `STAT_QUEUE_FULL`.
`ebpfdivert_get_event_fd()` returns an epoll descriptor that is readable whenever `recv` would not block.
After `ebpfdivert_shutdown(RECV)` the programs pass everything, and `recv` returns what was already captured,
then `-ESHUTDOWN`. All calls are thread-safe, and `ebpfdivert_close()` waits for calls in progress.
