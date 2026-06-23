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

struct divert_pkt_header {
    __u32 pkt_len;
    __u32 ifindex;
    __u16 direction;
    __u16 l2_len;
    __u32 cap_len;
} __attribute__((packed));

struct divert_packet_buffer {
    struct divert_pkt_header header;
    __u8 data[2048];
} __attribute__((packed));

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

struct divert_config {
    __u32 priority;
    __u32 snaplen;
    __u32 loop_prevention_mark;
} __attribute__((packed));

#endif // EBPFDIVERT_SHARED_H
