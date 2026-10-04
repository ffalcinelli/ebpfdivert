// SPDX-License-Identifier: GPL-2.0-or-later OR LGPL-3.0-or-later
#ifndef EBPFDIVERT_SHARED_H
#define EBPFDIVERT_SHARED_H

#ifdef __bpf__
// Kernel BPF compilation: types are provided by vmlinux.h
#else
#include <linux/types.h>
#endif

#define MAX_RULES 64

#define STAT_DIVERTED     0
#define STAT_DROPPED      1
#define STAT_SNIFFED      2
#define STAT_PARSING_ERR  3
#define STAT_RINGBUF_FULL 4
#define STAT_QUEUE_FULL   5
#define STAT_TOO_BIG      6
#define STAT_OWNER_GONE   7
#define STAT_MAX          8

#define REDIRECT_MARK_MASK 0x4D4A0000

#define MATCH_SRC_IP         (1 << 0)
#define MATCH_DST_IP         (1 << 1)
#define MATCH_SRC_PORT       (1 << 2)
#define MATCH_DST_PORT       (1 << 3)
#define MATCH_PROTO          (1 << 4)
#define MATCH_DIRECTION      (1 << 5)
#define MATCH_LOOPBACK       (1 << 6)
#define MATCH_FALSE          (1 << 7)
#define MATCH_ENABLED        (1 << 8)
#define MATCH_SNIFF          (1 << 9)
#define MATCH_DROP           (1 << 10)
#define MATCH_TTL            (1 << 11)
#define MATCH_TCP_FLAGS      (1 << 12)
#define MATCH_LPM_TRIE      (1 << 13)

/* Largest packet the BPF program copies to user space (a full GSO/GRO skb). */
#define DIVERT_MAX_PACKET    65536

/* divert_pkt_header.flags */
#define PKT_F_IMPOSTOR       (1 << 0)  /* carried an ebpfdivert injection mark */
#define PKT_F_LOOPBACK       (1 << 1)  /* seen on the loopback device */
#define PKT_F_SNIFFED        (1 << 2)  /* packet was not stolen */
#define PKT_F_FRAGMENT       (1 << 3)  /* IPv4/IPv6 fragment */
#define PKT_F_FORWARD        (1 << 4)  /* forwarded (NETWORK_FORWARD layer) */

/*
 * Ring buffer record: a fixed header followed by cap_len bytes of packet
 * data, starting at the L2 header (l2_len bytes, 0 for L3 devices).
 */
struct divert_pkt_header {
    __u32 pkt_len;          /* skb->len */
    __u32 ifindex;          /* device the packet was seen on */
    __u16 direction;        /* 1 = ingress, 2 = egress */
    __u16 l2_len;
    __u32 cap_len;          /* bytes of data following the header */
    __u64 timestamp;        /* bpf_ktime_get_ns() */
    __u32 ingress_ifindex;  /* skb->ingress_ifindex (0 = locally generated) */
    __u16 gso_size;         /* skb->gso_size, 0 if not a GSO skb */
    __u16 gso_segs;         /* skb->gso_segs */
    __u16 flags;            /* PKT_F_* */
    __u16 reserved;
    __u32 reserved2;
};

struct divert_packet_buffer {
    struct divert_pkt_header header;
    __u8 data[];
};

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

struct filter_rule_ipv6 {
    union {
        __u8  src_ip[16];
        __u64 src_ip_u64[2];
    };
    union {
        __u8  dst_ip[16];
        __u64 dst_ip_u64[2];
    };
    union {
        __u8  src_mask[16];
        __u64 src_mask_u64[2];
    };
    union {
        __u8  dst_mask[16];
        __u64 dst_mask_u64[2];
    };
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

/* divert_config.flags */
#define CFG_F_SHUTDOWN       (1 << 0)  /* pass everything (WinDivertShutdown RECV) */
#define CFG_F_FRAGMENTS      (1 << 1)  /* capture inbound IP fragments */
#define CFG_F_FORWARD        (1 << 2)  /* NETWORK_FORWARD layer instead of NETWORK */
#define CFG_F_FWD_CHECK      (1 << 3)  /* IP forwarding is on: FIB-check ingress */
#define CFG_F_NO_INBOUND     (1 << 4)  /* filter can never match inbound */
#define CFG_F_NO_OUTBOUND    (1 << 5)  /* filter can never match outbound */
#define CFG_F_SKIP_LO        (1 << 6)  /* lo attached only for injection */

struct divert_config {
    __u32 priority;             /* TC priority of this handle (lower = earlier) */
    __u32 snaplen;              /* max bytes copied per packet */
    __u32 loop_prevention_mark; /* upper 16 bits of the injection mark */
    __u32 lo_ifindex;           /* ifindex of the loopback device */
    __u32 flags;                /* CFG_F_* */
    __u32 reserved;
    /*
     * Owner liveness: user space refreshes heartbeat_ns (bpf_ktime_get_ns
     * clock) periodically.  Once it is older than heartbeat_timeout_ns the
     * owner is presumed dead and the program lets every packet through, so a
     * crashed process never keeps diverting or dropping traffic.  A zero
     * timeout disables the check (pinned global mode).
     */
    __u64 heartbeat_ns;
    __u64 heartbeat_timeout_ns;
};

/*
 * Injection marks (skb->mark), set by user space on the sockets it uses to
 * re-inject packets:
 *  - LOOP_PREVENTION_MARK | tc_priority: handles with the same or a higher
 *    priority (lower or equal TC priority) ignore the packet.
 *  - REDIRECT_MARK_MASK | target_ifindex: an inbound packet sent through
 *    `lo`, with SO_PRIORITY = REDIRECT_PRIO_MAGIC | tc_priority.  The lo
 *    ingress hook rewrites the mark to REDIRECTED_MARK | tc_priority (the
 *    redirect clears skb->priority but keeps the mark) and redirects the
 *    packet to target_ifindex ingress, where it becomes a
 *    LOOP_PREVENTION_MARK.
 */
#define LOOP_PREVENTION_MARK 0x4D490000
#define REDIRECT_PRIO_MAGIC  0x4D4B0000
#define REDIRECTED_MARK      0x4D4C0000


/****************************************************************************/
/* Event layers (FLOW, SOCKET): ebpfdivert_events.bpf.c                     */
/****************************************************************************/

#define EVENT_RULES_MAX     32

/* WINDIVERT_EVENT_* values */
#define DIVERT_EVENT_FLOW_ESTABLISHED  1
#define DIVERT_EVENT_FLOW_DELETED      2
#define DIVERT_EVENT_SOCKET_BIND       3
#define DIVERT_EVENT_SOCKET_CONNECT    4
#define DIVERT_EVENT_SOCKET_LISTEN     5
#define DIVERT_EVENT_SOCKET_ACCEPT     6
#define DIVERT_EVENT_SOCKET_CLOSE      7

/* divert_event.flags */
#define EVF_BLOCKED          (1 << 0)  /* the operation was refused */
#define EVF_UDP_RELEASE      (1 << 1)  /* internal: UDP socket released (FLOW) */

/* Ring buffer record of the event programs.  Addresses are 16 bytes in
 * network order, IPv4 as ::ffff:a.b.c.d; ports are in host order. */
struct divert_event {
    __u64 timestamp;
    __u64 endpoint_id;          /* socket cookie */
    __u64 parent_endpoint_id;
    __u32 pid;
    __u8  event;
    __u8  protocol;
    __u8  family;               /* 4 or 6 */
    __u8  flags;                /* EVF_* */
    __u16 local_port;
    __u16 remote_port;
    __u8  local_addr[16];
    __u8  remote_addr[16];
};

/* event_config.flags */
#define EVCFG_F_SOCKET       (1 << 0)  /* SOCKET layer (else FLOW) */
#define EVCFG_F_BLOCK        (1 << 1)  /* refuse matching bind/connect */
#define EVCFG_F_SHUTDOWN     (1 << 2)

struct event_config {
    __u32 flags;
    __u32 reserved;
    __u64 heartbeat_ns;
    __u64 heartbeat_timeout_ns;
};

/* event_rule.match_mask */
#define EVM_ENABLED    (1 << 0)
#define EVM_EVENT      (1 << 1)
#define EVM_PROTO      (1 << 2)
#define EVM_FAMILY     (1 << 3)
#define EVM_LPORT      (1 << 4)
#define EVM_RPORT      (1 << 5)
#define EVM_LADDR      (1 << 6)
#define EVM_RADDR      (1 << 7)
#define EVM_PID        (1 << 8)
#define EVM_LOOPBACK   (1 << 9)

/* One conjunction of an exactly lowered SOCKET-layer filter. */
struct event_rule {
    __u32 match_mask;
    __u32 invert_mask;
    __u32 pid_lo, pid_hi;
    __u16 event_mask;           /* bit n = event n */
    __u16 lport_lo, lport_hi;
    __u16 rport_lo, rport_hi;
    __u8  proto;
    __u8  family;
    __u8  loopback;
    __u8  reserved[3];
    __u8  laddr[16], lmask[16];
    __u8  raddr[16], rmask[16];
};

#endif // EBPFDIVERT_SHARED_H
