// SPDX-License-Identifier: GPL-2.0-or-later OR LGPL-3.0-or-later
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define TC_ACT_UNSPEC  (-1)
#define TC_ACT_OK      0
#define TC_ACT_SHOT    2
#define TC_ACT_STOLEN  4

#define STAT_DIVERTED 0
#define STAT_DROPPED  1
#define STAT_SNIFFED  2

struct divert_pkt_header {
    __u32 pkt_len;
    __u32 ifindex;
    __u16 direction;
    __u16 l2_len;
    __u32 pad;
};

struct divert_packet_buffer {
    struct divert_pkt_header header;
    __u8 data[2048];
};

#define MAX_RULES 64

struct filter_rule {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u16 match_mask;
    __u16 invert_mask;
    __u8  proto;
    __u8  direction;
    __u8  loopback;
    __u8  ttl;
    __u8  tcp_flags;
    __u8  tcp_flags_mask;
};

struct filter_rule_ipv6 {
    __u8  src_ip[16] __attribute__((aligned(8)));
    __u8  dst_ip[16] __attribute__((aligned(8)));
    __u16 src_port;
    __u16 dst_port;
    __u16 match_mask;
    __u16 invert_mask;
    __u8  proto;
    __u8  direction;
    __u8  loopback;
    __u8  ttl;
    __u8  tcp_flags;
    __u8  tcp_flags_mask;
} __attribute__((aligned(8)));

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

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} pcap_ringbuf SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, MAX_RULES);
    __type(key, __u32);
    __type(value, struct filter_rule);
} filter_rules SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, MAX_RULES);
    __type(key, __u32);
    __type(value, struct filter_rule_ipv6);
} filter_rules_ipv6 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 3);
    __type(key, __u32);
    __type(value, __u64);
} stats_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} config_map SEC(".maps");

static __always_inline void increment_stat(__u32 key) {
    __u64 *val = bpf_map_lookup_elem(&stats_map, &key);
    if (val) {
        *val += 1;
    }
}

struct parsed_packet {
    __u32 src_ip;
    __u8  src_ip6[16] __attribute__((aligned(8)));
    __u32 dst_ip;
    __u8  dst_ip6[16] __attribute__((aligned(8)));
    __u16 src_port;
    __u16 dst_port;
    __u16 l2_len;
    __u32 ifindex;
    __u8  proto;
    __u8  ver;
    __u8  ttl;
    __u8  tcp_flags;
    __u8  parsed_ok;
};

static __always_inline int parse_packet(struct __sk_buff *skb, struct parsed_packet *pkt) {
    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;

    __u16 proto = bpf_ntohs(skb->protocol);
    __u16 l2_len = 0;
    int found = 0;

    // Detect L2 length based on protocol and packet structure
    // 1. Try Ethernet (14 bytes)
    if (data + 14 <= data_end) {
        __u16 ethertype = bpf_ntohs(*(__u16 *)((char *)data + 12));
        if (ethertype == 0x0800 || ethertype == 0x86DD) {
            l2_len = 14;
            found = 1;
        } else if (ethertype == 0x8100 || ethertype == 0x88A8) {
            // VLAN or QinQ
            if (data + 18 <= data_end) {
                __u16 inner_ethertype = bpf_ntohs(*(__u16 *)((char *)data + 16));
                if (inner_ethertype == 0x0800 || inner_ethertype == 0x86DD) {
                    l2_len = 18;
                    found = 1;
                }
            }
        }
    }

    // 2. Try raw IP (0 bytes)
    if (!found && data + 20 <= data_end) {
        __u8 ver = (*(__u8 *)data) >> 4;
        if (ver == 4 || ver == 6) {
            l2_len = 0;
            found = 1;
        }
    }

    // 3. Try Null/Loopback/Tunnel (4 bytes)
    if (!found && (char *)data + 4 + 20 <= (char *)data_end) {
        __u8 ver = *(((__u8 *)data) + 4) >> 4;
        if (ver == 4 || ver == 6) {
            l2_len = 4;
            found = 1;
        }
    }

    if (!found) {
        pkt->parsed_ok = 0;
        return 0;
    }

    pkt->l2_len = l2_len;
    pkt->ifindex = skb->ifindex;

    void *l3_ptr = (char *)data + l2_len;
    if (l3_ptr + 1 > data_end) {
        pkt->parsed_ok = 0;
        return 0;
    }
    pkt->ver = (*(__u8 *)l3_ptr) >> 4;

    if (pkt->ver == 4) {
        struct iphdr *ip = l3_ptr;
        if ((void *)(ip + 1) > data_end) {
            pkt->parsed_ok = 0;
            return 0;
        }
        pkt->src_ip = bpf_ntohl(ip->saddr);
        pkt->dst_ip = bpf_ntohl(ip->daddr);
        pkt->proto = ip->protocol;
        pkt->ttl = ip->ttl;

        __u8 ihl = ip->ihl;
        if (ihl < 5) {
            pkt->parsed_ok = 0;
            return 0;
        }

        void *transport_ptr = (char *)l3_ptr + (ihl * 4);

        if (pkt->proto == 6) { // TCP
            struct tcphdr *tcp = transport_ptr;
            if ((void *)(tcp + 1) <= data_end) {
                pkt->src_port = bpf_ntohs(tcp->source);
                pkt->dst_port = bpf_ntohs(tcp->dest);
                pkt->tcp_flags = *((__u8 *)tcp + 13);
            }
        } else if (pkt->proto == 17) { // UDP
            struct udphdr *udp = transport_ptr;
            if ((void *)(udp + 1) <= data_end) {
                pkt->src_port = bpf_ntohs(udp->source);
                pkt->dst_port = bpf_ntohs(udp->dest);
            }
        }
    } else if (pkt->ver == 6) {
        struct ipv6hdr *ip6 = l3_ptr;
        if ((void *)(ip6 + 1) > data_end) {
            pkt->parsed_ok = 0;
            return 0;
        }
        pkt->proto = ip6->nexthdr;
        pkt->ttl = ip6->hop_limit;

        __builtin_memcpy(pkt->src_ip6, ip6->saddr.in6_u.u6_addr8, 16);
        __builtin_memcpy(pkt->dst_ip6, ip6->daddr.in6_u.u6_addr8, 16);

        void *transport_ptr = (void *)(ip6 + 1);

        if (pkt->proto == 6) { // TCP
            struct tcphdr *tcp = transport_ptr;
            if ((void *)(tcp + 1) <= data_end) {
                pkt->src_port = bpf_ntohs(tcp->source);
                pkt->dst_port = bpf_ntohs(tcp->dest);
                pkt->tcp_flags = *((__u8 *)tcp + 13);
            }
        } else if (pkt->proto == 17) { // UDP
            struct udphdr *udp = transport_ptr;
            if ((void *)(udp + 1) <= data_end) {
                pkt->src_port = bpf_ntohs(udp->source);
                pkt->dst_port = bpf_ntohs(udp->dest);
            }
        }
    } else {
        pkt->parsed_ok = 0;
        return 0;
    }

    pkt->parsed_ok = 1;
    return 1;
}

static __always_inline int matches_rule_ipv4(struct parsed_packet *pkt, struct filter_rule *rule, __u8 direction) {
    if (!(rule->match_mask & MATCH_ENABLED)) return 0;
    if (rule->match_mask & MATCH_FALSE) return 0;

    if (!pkt->parsed_ok) {
        if (rule->match_mask == MATCH_ENABLED) return 1;
        return 0;
    }

    if (pkt->ver != 4) return 0;

    if ((rule->match_mask & MATCH_SRC_IP) && ((pkt->src_ip == rule->src_ip) == !!(rule->invert_mask & MATCH_SRC_IP))) return 0;
    if ((rule->match_mask & MATCH_DST_IP) && ((pkt->dst_ip == rule->dst_ip) == !!(rule->invert_mask & MATCH_DST_IP))) return 0;
    if ((rule->match_mask & MATCH_SRC_PORT) && ((pkt->src_port == rule->src_port) == !!(rule->invert_mask & MATCH_SRC_PORT))) return 0;
    if ((rule->match_mask & MATCH_DST_PORT) && ((pkt->dst_port == rule->dst_port) == !!(rule->invert_mask & MATCH_DST_PORT))) return 0;
    if ((rule->match_mask & MATCH_PROTO) && ((pkt->proto == rule->proto) == !!(rule->invert_mask & MATCH_PROTO))) return 0;
    if ((rule->match_mask & MATCH_DIRECTION) && ((direction == rule->direction) == !!(rule->invert_mask & MATCH_DIRECTION))) return 0;
    if ((rule->match_mask & MATCH_TTL) && ((pkt->ttl == rule->ttl) == !!(rule->invert_mask & MATCH_TTL))) return 0;
    if ((rule->match_mask & MATCH_TCP_FLAGS) && (pkt->tcp_flags & rule->tcp_flags_mask) != rule->tcp_flags) return 0;

    if (rule->match_mask & MATCH_LOOPBACK) {
        int is_lo = (pkt->ifindex == 1);
        if (is_lo != rule->loopback) return 0;
    }

    return 1;
}

static __always_inline int matches_rule_ipv6(struct parsed_packet *pkt, struct filter_rule_ipv6 *rule, __u8 direction) {
    if (!(rule->match_mask & MATCH_ENABLED)) return 0;
    if (rule->match_mask & MATCH_FALSE) return 0;

    if (!pkt->parsed_ok) {
        if (rule->match_mask == MATCH_ENABLED) return 1;
        return 0;
    }

    if (pkt->ver != 6) return 0;

    if (rule->match_mask & MATCH_SRC_IP) {
        __u64 *p1 = (__u64 *)pkt->src_ip6;
        __u64 *r1 = (__u64 *)rule->src_ip;
        int ip_match = (p1[0] == r1[0] && p1[1] == r1[1]);
        if (ip_match == !!(rule->invert_mask & MATCH_SRC_IP)) return 0;
    }

    if (rule->match_mask & MATCH_DST_IP) {
        __u64 *p2 = (__u64 *)pkt->dst_ip6;
        __u64 *r2 = (__u64 *)rule->dst_ip;
        int ip_match = (p2[0] == r2[0] && p2[1] == r2[1]);
        if (ip_match == !!(rule->invert_mask & MATCH_DST_IP)) return 0;
    }

    if ((rule->match_mask & MATCH_SRC_PORT) && ((pkt->src_port == rule->src_port) == !!(rule->invert_mask & MATCH_SRC_PORT))) return 0;
    if ((rule->match_mask & MATCH_DST_PORT) && ((pkt->dst_port == rule->dst_port) == !!(rule->invert_mask & MATCH_DST_PORT))) return 0;
    if ((rule->match_mask & MATCH_PROTO) && ((pkt->proto == rule->proto) == !!(rule->invert_mask & MATCH_PROTO))) return 0;
    if ((rule->match_mask & MATCH_DIRECTION) && ((direction == rule->direction) == !!(rule->invert_mask & MATCH_DIRECTION))) return 0;
    if ((rule->match_mask & MATCH_TTL) && ((pkt->ttl == rule->ttl) == !!(rule->invert_mask & MATCH_TTL))) return 0;
    if ((rule->match_mask & MATCH_TCP_FLAGS) && (pkt->tcp_flags & rule->tcp_flags_mask) != rule->tcp_flags) return 0;

    if (rule->match_mask & MATCH_LOOPBACK) {
        int is_lo = (pkt->ifindex == 1);
        if (is_lo != rule->loopback) return 0;
    }

    return 1;
}

static __always_inline int process_packet(struct __sk_buff *skb, __u8 direction) {
    __u32 key = 0;
    __u32 *my_prio_ptr = bpf_map_lookup_elem(&config_map, &key);
    __u32 my_prio = my_prio_ptr ? *my_prio_ptr : 0;

    // LOOP_PREVENTION_MARK mask: 0x4D490000 | priority
    if ((skb->mark & 0xFFFF0000) == 0x4D490000) {
        __u16 inject_prio = skb->mark & 0xFFFF;
        // Ignore if we injected it, or if our priority is higher/equal (lower/equal integer)
        // than the injector's priority. This allows lower priority handles (higher integer)
        // to see reinjected packets.
        if (my_prio <= inject_prio) return TC_ACT_UNSPEC;
    }

    bpf_skb_pull_data(skb, 64);

    struct parsed_packet pkt = {0};
    parse_packet(skb, &pkt);

    int matched = 0;
    __u16 match_mask = 0;

    // 1. Process IPv4/Generic rules
    #pragma unroll
    for (__u32 i = 0; i < MAX_RULES; i++) {
        __u32 k = i;
        struct filter_rule *rule = bpf_map_lookup_elem(&filter_rules, &k);
        if (!rule || rule->match_mask == 0) break;
        if (matches_rule_ipv4(&pkt, rule, direction)) {
            matched = 1;
            match_mask = rule->match_mask;
            break;
        }
    }

    // 2. Process IPv6-specific rules (if packet is IPv6 and no generic rule matched)
    if (!matched && pkt.parsed_ok && pkt.ver == 6) {
        #pragma unroll
        for (__u32 i = 0; i < MAX_RULES; i++) {
            __u32 k = i;
            struct filter_rule_ipv6 *rule = bpf_map_lookup_elem(&filter_rules_ipv6, &k);
            if (!rule || rule->match_mask == 0) break;
            if (matches_rule_ipv6(&pkt, rule, direction)) {
                matched = 1;
                match_mask = rule->match_mask;
                break;
            }
        }
    }

    if (!matched) return TC_ACT_UNSPEC;

    if (match_mask & MATCH_DROP) {
        increment_stat(STAT_DROPPED);
        return TC_ACT_SHOT;
    }

    struct divert_packet_buffer *buf = bpf_ringbuf_reserve(&pcap_ringbuf, sizeof(struct divert_packet_buffer), 0);
    if (!buf) return TC_ACT_UNSPEC;

    buf->header.pkt_len = skb->len;
    buf->header.ifindex = skb->ifindex;
    buf->header.direction = (__u16)direction;
    buf->header.l2_len = pkt.parsed_ok ? pkt.l2_len : 0;
    buf->header.pad = 0xDEADC0DE;

    __u32 to_load = skb->len;
    if (to_load > 2048) to_load = 2048;
    if (to_load > 0) {
        bpf_skb_load_bytes(skb, 0, buf->data, ((to_load - 1) & 0x7FF) + 1);
    }

    bpf_ringbuf_submit(buf, 0);

    if (match_mask & MATCH_SNIFF) {
        increment_stat(STAT_SNIFFED);
        return TC_ACT_UNSPEC;
    }

    increment_stat(STAT_DIVERTED);
    return TC_ACT_STOLEN;
}

SEC("classifier")
int tc_divert_ingress(struct __sk_buff *skb) {
    return process_packet(skb, 1);
}

SEC("classifier")
int tc_divert_egress(struct __sk_buff *skb) {
    return process_packet(skb, 2);
}

char _license[] SEC("license") = "Dual GPL/LGPL";
