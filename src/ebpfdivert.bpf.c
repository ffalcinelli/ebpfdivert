// SPDX-License-Identifier: GPL-2.0-or-later OR LGPL-3.0-or-later
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "ebpfdivert_shared.h"

#define TC_ACT_UNSPEC  (-1)
#define TC_ACT_OK      0
#define TC_ACT_SHOT    2
#define TC_ACT_STOLEN  4

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
    __uint(max_entries, 6);
    __type(key, __u32);
    __type(value, __u64);
} stats_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct divert_config);
} config_map SEC(".maps");

const volatile __u32 default_snaplen = 2048;

static __always_inline void increment_stat(__u32 key) {
    __u64 *val = bpf_map_lookup_elem(&stats_map, &key);
    if (val) {
        *val += 1;
    }
}

struct parsed_packet {
    __u32 src_ip;
    union {
        __u8  src_ip6[16] __attribute__((aligned(8)));
        __u64 src_ip6_u64[2];
    };
    __u32 dst_ip;
    union {
        __u8  dst_ip6[16] __attribute__((aligned(8)));
        __u64 dst_ip6_u64[2];
    };
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

    bpf_printk("parse_packet: len=%d, proto=%x, data_len=%d", skb->len, bpf_ntohs(skb->protocol), (int)(data_end - data));

    __u16 l2_len = 0;
    int found = 0;

    // Detect L2 length based on protocol and packet structure
    // 1. Try Ethernet (14 bytes)
    if (data + 14 <= data_end) {
        __u16 ethertype = bpf_ntohs(*(__u16 *)((char *)data + 12));
        bpf_printk("  14B check: %02x %02x %02x %02x ... ethertype=%x", 
                   *(__u8 *)data, *((__u8 *)data+1), *((__u8 *)data+2), *((__u8 *)data+3), ethertype);
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
                } else if (inner_ethertype == 0x8100) {
                    // QinQ: check for another VLAN tag (4 more bytes)
                    if (data + 22 <= data_end) {
                        __u16 inner_inner_ethertype = bpf_ntohs(*(__u16 *)((char *)data + 20));
                        if (inner_inner_ethertype == 0x0800 || inner_inner_ethertype == 0x86DD) {
                            l2_len = 22;
                            found = 1;
                        }
                    }
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
        } else if (pkt->proto == 1) { // ICMP
            struct icmphdr *icmp = transport_ptr;
            if ((void *)(icmp + 1) <= data_end) {
                pkt->src_port = icmp->type;
                pkt->dst_port = icmp->code;
            }
        }
    } else if (pkt->ver == 6) {
        struct ipv6hdr *ip6 = l3_ptr;
        if ((void *)(ip6 + 1) > data_end) {
            pkt->parsed_ok = 0;
            return 0;
        }
        pkt->ttl = ip6->hop_limit;

        __builtin_memcpy(pkt->src_ip6, ip6->saddr.in6_u.u6_addr8, 16);
        __builtin_memcpy(pkt->dst_ip6, ip6->daddr.in6_u.u6_addr8, 16);

        #define IPPROTO_HOPOPTS  0
        #define IPPROTO_ROUTING  43
        #define IPPROTO_FRAGMENT 44
        #define IPPROTO_DSTOPTS  60

        __u8 nexthdr = ip6->nexthdr;
        void *transport_ptr = (void *)(ip6 + 1);

        #define MAX_EXT_HEADERS 4
        #pragma unroll
        for (int i = 0; i < MAX_EXT_HEADERS; i++) {
            if (nexthdr != IPPROTO_HOPOPTS && nexthdr != IPPROTO_ROUTING &&
                nexthdr != IPPROTO_FRAGMENT && nexthdr != IPPROTO_DSTOPTS) {
                break;
            }

            if (transport_ptr + 8 > data_end) {
                pkt->parsed_ok = 0;
                return 0;
            }

            __u32 hdr_len = 0;
            if (nexthdr == IPPROTO_FRAGMENT) {
                hdr_len = 8;
            } else {
                hdr_len = ((*((__u8 *)transport_ptr + 1)) + 1) << 3;
            }
            hdr_len &= 0x7FF;

            if (transport_ptr + hdr_len > data_end) {
                pkt->parsed_ok = 0;
                return 0;
            }

            nexthdr = *((__u8 *)transport_ptr);
            transport_ptr += hdr_len;
        }
        pkt->proto = nexthdr;

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
        } else if (pkt->proto == 58) { // ICMPv6
            struct icmp6hdr *icmp6 = transport_ptr;
            if ((void *)(icmp6 + 1) <= data_end) {
                pkt->src_port = icmp6->icmp6_type;
                pkt->dst_port = icmp6->icmp6_code;
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

    if ((rule->match_mask & MATCH_SRC_IP) && (((pkt->src_ip & rule->src_mask) == (rule->src_ip & rule->src_mask)) == !!(rule->invert_mask & MATCH_SRC_IP))) return 0;
    if ((rule->match_mask & MATCH_DST_IP) && (((pkt->dst_ip & rule->dst_mask) == (rule->dst_ip & rule->dst_mask)) == !!(rule->invert_mask & MATCH_DST_IP))) return 0;
    if ((rule->match_mask & MATCH_SRC_PORT) && (((pkt->src_port >= rule->src_port_start && pkt->src_port <= rule->src_port_end)) == !!(rule->invert_mask & MATCH_SRC_PORT))) return 0;
    if ((rule->match_mask & MATCH_DST_PORT) && (((pkt->dst_port >= rule->dst_port_start && pkt->dst_port <= rule->dst_port_end)) == !!(rule->invert_mask & MATCH_DST_PORT))) return 0;
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
        int ip_match = ((pkt->src_ip6_u64[0] & rule->src_mask_u64[0]) == (rule->src_ip_u64[0] & rule->src_mask_u64[0])) &&
                       ((pkt->src_ip6_u64[1] & rule->src_mask_u64[1]) == (rule->src_ip_u64[1] & rule->src_mask_u64[1]));
        if (ip_match == !!(rule->invert_mask & MATCH_SRC_IP)) return 0;
    }

    if (rule->match_mask & MATCH_DST_IP) {
        int ip_match = ((pkt->dst_ip6_u64[0] & rule->dst_mask_u64[0]) == (rule->dst_ip_u64[0] & rule->dst_mask_u64[0])) &&
                       ((pkt->dst_ip6_u64[1] & rule->dst_mask_u64[1]) == (rule->dst_ip_u64[1] & rule->dst_mask_u64[1]));
        if (ip_match == !!(rule->invert_mask & MATCH_DST_IP)) return 0;
    }

    if ((rule->match_mask & MATCH_SRC_PORT) && (((pkt->src_port >= rule->src_port_start && pkt->src_port <= rule->src_port_end)) == !!(rule->invert_mask & MATCH_SRC_PORT))) return 0;
    if ((rule->match_mask & MATCH_DST_PORT) && (((pkt->dst_port >= rule->dst_port_start && pkt->dst_port <= rule->dst_port_end)) == !!(rule->invert_mask & MATCH_DST_PORT))) return 0;
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
    struct divert_config *cfg = bpf_map_lookup_elem(&config_map, &key);
    __u32 my_prio = cfg ? cfg->priority : 0;
    __u32 prevent_mark = (cfg && cfg->loop_prevention_mark) ? cfg->loop_prevention_mark : 0x4D490000;
    __u32 snap = (cfg && cfg->snaplen) ? cfg->snaplen : default_snaplen;

    // LOOP_PREVENTION_MARK mask: prevent_mark | priority
    if ((skb->mark & 0xFFFF0000) == (prevent_mark & 0xFFFF0000)) {
        __u16 inject_prio = skb->mark & 0xFFFF;
        // Ignore if we injected it, or if our priority is higher/equal (lower/equal integer)
        // than the injector's priority. This allows lower priority handles (higher integer)
        // to see reinjected packets.
        if (my_prio <= inject_prio) return TC_ACT_UNSPEC;
    }

    if ((skb->mark & 0xFFFF0000) == REDIRECT_MARK_MASK) {
        return TC_ACT_UNSPEC;
    }

    __u32 pull_len = skb->len;
    if (pull_len > 128) {
        pull_len = 128;
    }
    if (bpf_skb_pull_data(skb, pull_len) < 0) {
        increment_stat(STAT_PARSING_ERR);
        return TC_ACT_UNSPEC;
    }

    struct parsed_packet pkt = {0};
    if (!parse_packet(skb, &pkt)) {
        increment_stat(STAT_PARSING_ERR);
    }

    int matched = 0;
    __u16 match_mask = 0;

    // 1. Process IPv4/Generic rules
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
    if (!buf) {
        increment_stat(STAT_RINGBUF_FULL);
        return TC_ACT_UNSPEC;
    }

    buf->header.pkt_len = skb->len;
    buf->header.ifindex = skb->ifindex;
    buf->header.direction = (__u16)direction;
    buf->header.l2_len = pkt.parsed_ok ? pkt.l2_len : 0;

    __u32 to_load = skb->len;
    __u32 max_len = snap;
    if (max_len > 2048) max_len = 2048;
    if (to_load > max_len) to_load = max_len;

    buf->header.cap_len = to_load;
    if (to_load > 0) {
        int ret = bpf_skb_load_bytes(skb, 0, buf->data, ((to_load - 1) & 0x7FF) + 1);
        if (ret < 0) {
            bpf_ringbuf_discard(buf, 0);
            increment_stat(STAT_PARSING_ERR);
            return TC_ACT_UNSPEC;
        }
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
    if ((skb->mark & 0xFFFF0000) == REDIRECT_MARK_MASK) {
        __u32 target_ifindex = skb->mark & 0xFFFF;
        if (skb->ifindex == target_ifindex) {
            return TC_ACT_UNSPEC;
        }
        return bpf_redirect(target_ifindex, BPF_F_INGRESS);
    }
    return process_packet(skb, 1);
}

SEC("classifier")
int tc_divert_egress(struct __sk_buff *skb) {
    return process_packet(skb, 2);
}

char _license[] SEC("license") = "GPL";
