# eBPFDivert Filtering Rules Reference

`ebpfdivert` uses a structured kernel-side rule engine stored in BPF maps. Users configure filtering rules to determine which packets are intercepted, dropped, or sniffed.

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
| `MATCH_LOOPBACK` | `1 << 6` | Verify loopback status (interface index 1). |
| `MATCH_TTL` | `1 << 11` | Verify TTL / Hop Limit. |
| `MATCH_TCP_FLAGS` | `1 << 12` | Verify TCP flags. |

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

Use the `ebpfdivert-cli` rules utility to configure the BPF maps:

```bash
# Sniff (monitor) all inbound TCP port 80 traffic
sudo ./ebpfdivert-cli rules add-ext 0 sniff --proto tcp --dst-port 80 --direction ingress

# Drop all outbound UDP traffic except to port 53 (DNS)
sudo ./ebpfdivert-cli rules add-ext 1 drop --proto udp --dst-port 53 --direction egress --invert dst-port

# Divert any packets with TCP SYN flag set
sudo ./ebpfdivert-cli rules add-ext 2 divert --proto tcp --tcp-flags SYN --tcp-flags-mask SYN
```
