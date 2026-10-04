# eBPFDivert kernel rules reference

The BPF program matches packets against a table of up to 64 conjunctive rules per address family
(`MAX_RULES`), in index order; the first matching rule decides the action.

- **Handles** (`ebpfdivert_open`) never expose this table. The library fills it by lowering the WinDivert filter
  (`src/prefilter.c`). When the lowering is not exact, the library evaluates the full filter in user space. See
  [architecture.md](architecture.md).
- **Pinned global mode** (`ebpfdivert-cli load` / `rules`) lets you write the table directly. Its maps are pinned
  under `/sys/fs/bpf/ebpfdivert/`. This document describes that table.

---

## 1. Rule Structures

In `ebpfdivert_shared.h`, filtering rules are structured as C structs:

### IPv4/Generic Rule: `struct filter_rule`
```c
struct filter_rule {
    __u32 src_ip;
    __u32 dst_ip;
    __u32 src_mask;
    __u32 dst_mask;
    union {
        __u16 src_port_start;
        __u16 icmp_type_start;
    };
    union {
        __u16 src_port_end;
        __u16 icmp_type_end;
    };
    union {
        __u16 dst_port_start;
        __u16 icmp_code_start;
    };
    union {
        __u16 dst_port_end;
        __u16 icmp_code_end;
    };
    __u16 match_mask;
    __u16 invert_mask;
    __u8  proto;
    __u8  direction;
    __u8  loopback;
    __u8  ttl;
    __u8  tcp_flags;
    __u8  tcp_flags_mask;
} __attribute__((packed));
```

### IPv6 Rule: `struct filter_rule_ipv6`
Identical fields to `struct filter_rule`, but `src_ip`, `dst_ip`, `src_mask`, and `dst_mask` are 16-byte arrays (`__u8 src_ip[16]`) instead of 4-byte integers.

---

## 2. Match Mask (`match_mask`)

Each bit in the `match_mask` specifies whether the driver should evaluate that criteria:

| Mask Constant | Bit Value | Description |
| :--- | :--- | :--- |
| `MATCH_ENABLED` | `1 << 8` | The rule is active (required for all active rules). |
| `MATCH_FALSE` | `1 << 7` | The rule will never match (short-circuit). |
| `MATCH_SRC_IP` | `1 << 0` | Verify source IP / mask. |
| `MATCH_DST_IP` | `1 << 1` | Verify destination IP / mask. |
| `MATCH_SRC_PORT` | `1 << 2` | Verify source port range (or ICMP type). |
| `MATCH_DST_PORT` | `1 << 3` | Verify destination port range (or ICMP code). |
| `MATCH_PROTO` | `1 << 4` | Verify protocol (IP/NextHeader number). |
| `MATCH_DIRECTION` | `1 << 5` | Verify direction (1=ingress, 2=egress). |
| `MATCH_LOOPBACK` | `1 << 6` | Verify loopback status (packet on the loopback interface). |
| `MATCH_TTL` | `1 << 11` | Verify TTL / Hop Limit. |
| `MATCH_TCP_FLAGS` | `1 << 12` | Verify TCP flags. |
| `MATCH_LPM_TRIE` | `1 << 13` | Match source/destination addresses against the `ipv4_lpm_trie`/`ipv6_lpm_trie` maps instead of the rule's address/mask. |

---

## 3. Logical Inversion (`invert_mask`)

Any field matched via `match_mask` can have its logic inverted by setting its corresponding bit in the `invert_mask`. 
For example, if `MATCH_DST_PORT` is set in both `match_mask` and `invert_mask`, the rule matches any destination port *outside* the specified port range.

---

## 4. Actions

An action is defined by setting the corresponding action bit in the `match_mask`:

- **Divert** (Default action if no action mask bits are set):
  - Copies packet metadata and payload to user-space ring buffer.
  - Returns `TC_ACT_STOLEN` to the kernel, stealing it from the standard network path.
- **Sniff** (`MATCH_SNIFF` = `1 << 9`):
  - Copies packet metadata and payload to user-space ring buffer.
  - Returns `TC_ACT_OK` to the kernel, allowing the packet to proceed normally.
- **Drop** (`MATCH_DROP` = `1 << 10`):
  - Skips copy to ring buffer.
  - Returns `TC_ACT_SHOT` to the kernel, discarding the packet immediately.

---

## 5. Command-Line Examples

Load the pinned program, then configure its rules with `ebpfdivert-cli`:

```bash
sudo ./ebpfdivert-cli load all        # embedded BPF object, all interfaces

# Sniff (monitor) all inbound TCP port 80 traffic
sudo ./ebpfdivert-cli rules add-ext 0 sniff --proto tcp --dst-port 80 --direction ingress

# Drop all outbound UDP traffic except to port 53 (DNS)
sudo ./ebpfdivert-cli rules add-ext 1 drop --proto udp --dst-port 53 --direction egress --invert dst-port

# Divert any packets with TCP SYN flag set
sudo ./ebpfdivert-cli rules add-ext 2 divert --proto tcp --tcp-flags SYN --tcp-flags-mask SYN

sudo ./ebpfdivert-cli stats
sudo ./ebpfdivert-cli unload all
```
