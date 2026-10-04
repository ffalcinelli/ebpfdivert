// SPDX-License-Identifier: GPL-2.0-or-later OR LGPL-3.0-or-later
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "ebpfdivert_shared.h"

#define TC_ACT_UNSPEC  (-1)
#define TC_ACT_OK      0
#define TC_ACT_SHOT    2
#define TC_ACT_STOLEN  4

#define DIR_INGRESS    1
#define DIR_EGRESS     2

#define PACKET_HOST    0

#define ETH_P_IP       0x0800
#define ETH_P_IPV6     0x86DD

#define AF_INET        2
#define AF_INET6       10

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

struct bpf_lpm_trie_key_u4 {
    __u32 prefixlen;
    __u32 ipv4_addr;
};

struct bpf_lpm_trie_key_u6 {
    __u32 prefixlen;
    __u8 ipv6_addr[16];
};

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 1024);
    __type(key, struct bpf_lpm_trie_key_u4);
    __type(value, __u32);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} ipv4_lpm_trie SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 1024);
    __type(key, struct bpf_lpm_trie_key_u6);
    __type(value, __u32);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} ipv6_lpm_trie SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, STAT_MAX);
    __type(key, __u32);
    __type(value, __u64);
} stats_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct divert_config);
} config_map SEC(".maps");


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
    __u8  fragment;
    __u8  is_lo;
};

static __always_inline int parse_packet(struct __sk_buff *skb, struct parsed_packet *pkt) {
    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;


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

        __u16 frag_off = bpf_ntohs(ip->frag_off);
        if (frag_off & 0x3FFF) {
            pkt->fragment = 1;
        }

        void *transport_ptr = (char *)l3_ptr + (ihl * 4);

        if (frag_off & 0x1FFF) {
            // Non-first fragment: no transport header.
        } else if (pkt->proto == 6) { // TCP
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
                pkt->fragment = 1;
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

        if (pkt->fragment) {
            // Transport ports are only meaningful in the first fragment;
            // like WinDivert, fragments carry no transport header.
        } else if (pkt->proto == 6) { // TCP
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

    if (!pkt->parsed_ok || pkt->ver != 4) return 0;

    if (rule->match_mask & MATCH_LPM_TRIE) {
        if (rule->match_mask & MATCH_SRC_IP) {
            struct bpf_lpm_trie_key_u4 key = {
                .prefixlen = 32,
                .ipv4_addr = bpf_htonl(pkt->src_ip)
            };
            __u32 *val = bpf_map_lookup_elem(&ipv4_lpm_trie, &key);
            if (!val || !(*val & MATCH_SRC_IP)) {
                if (!(rule->invert_mask & MATCH_SRC_IP)) return 0;
            } else {
                if (rule->invert_mask & MATCH_SRC_IP) return 0;
            }
        }
        if (rule->match_mask & MATCH_DST_IP) {
            struct bpf_lpm_trie_key_u4 key = {
                .prefixlen = 32,
                .ipv4_addr = bpf_htonl(pkt->dst_ip)
            };
            __u32 *val = bpf_map_lookup_elem(&ipv4_lpm_trie, &key);
            if (!val || !(*val & MATCH_DST_IP)) {
                if (!(rule->invert_mask & MATCH_DST_IP)) return 0;
            } else {
                if (rule->invert_mask & MATCH_DST_IP) return 0;
            }
        }
    } else {
        if ((rule->match_mask & MATCH_SRC_IP) && (((pkt->src_ip & rule->src_mask) == (rule->src_ip & rule->src_mask)) == !!(rule->invert_mask & MATCH_SRC_IP))) return 0;
        if ((rule->match_mask & MATCH_DST_IP) && (((pkt->dst_ip & rule->dst_mask) == (rule->dst_ip & rule->dst_mask)) == !!(rule->invert_mask & MATCH_DST_IP))) return 0;
    }
    if ((rule->match_mask & MATCH_SRC_PORT) && (((pkt->src_port >= rule->src_port_start && pkt->src_port <= rule->src_port_end)) == !!(rule->invert_mask & MATCH_SRC_PORT))) return 0;
    if ((rule->match_mask & MATCH_DST_PORT) && (((pkt->dst_port >= rule->dst_port_start && pkt->dst_port <= rule->dst_port_end)) == !!(rule->invert_mask & MATCH_DST_PORT))) return 0;
    if ((rule->match_mask & MATCH_PROTO) && ((pkt->proto == rule->proto) == !!(rule->invert_mask & MATCH_PROTO))) return 0;
    if ((rule->match_mask & MATCH_DIRECTION) && ((direction == rule->direction) == !!(rule->invert_mask & MATCH_DIRECTION))) return 0;
    if ((rule->match_mask & MATCH_TTL) && ((pkt->ttl == rule->ttl) == !!(rule->invert_mask & MATCH_TTL))) return 0;
    if ((rule->match_mask & MATCH_TCP_FLAGS) && (((pkt->tcp_flags & rule->tcp_flags_mask) == rule->tcp_flags) == !!(rule->invert_mask & MATCH_TCP_FLAGS))) return 0;

    if ((rule->match_mask & MATCH_LOOPBACK) && pkt->is_lo != rule->loopback) return 0;

    return 1;
}

static __always_inline int matches_rule_ipv6(struct parsed_packet *pkt, struct filter_rule_ipv6 *rule, __u8 direction) {
    if (!(rule->match_mask & MATCH_ENABLED)) return 0;
    if (rule->match_mask & MATCH_FALSE) return 0;

    if (!pkt->parsed_ok || pkt->ver != 6) return 0;

    if (rule->match_mask & MATCH_LPM_TRIE) {
        if (rule->match_mask & MATCH_SRC_IP) {
            struct bpf_lpm_trie_key_u6 key = { .prefixlen = 128 };
            __builtin_memcpy(key.ipv6_addr, pkt->src_ip6, 16);
            __u32 *val = bpf_map_lookup_elem(&ipv6_lpm_trie, &key);
            if (!val || !(*val & MATCH_SRC_IP)) {
                if (!(rule->invert_mask & MATCH_SRC_IP)) return 0;
            } else {
                if (rule->invert_mask & MATCH_SRC_IP) return 0;
            }
        }
        if (rule->match_mask & MATCH_DST_IP) {
            struct bpf_lpm_trie_key_u6 key = { .prefixlen = 128 };
            __builtin_memcpy(key.ipv6_addr, pkt->dst_ip6, 16);
            __u32 *val = bpf_map_lookup_elem(&ipv6_lpm_trie, &key);
            if (!val || !(*val & MATCH_DST_IP)) {
                if (!(rule->invert_mask & MATCH_DST_IP)) return 0;
            } else {
                if (rule->invert_mask & MATCH_DST_IP) return 0;
            }
        }
    } else {
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
    }

    if ((rule->match_mask & MATCH_SRC_PORT) && (((pkt->src_port >= rule->src_port_start && pkt->src_port <= rule->src_port_end)) == !!(rule->invert_mask & MATCH_SRC_PORT))) return 0;
    if ((rule->match_mask & MATCH_DST_PORT) && (((pkt->dst_port >= rule->dst_port_start && pkt->dst_port <= rule->dst_port_end)) == !!(rule->invert_mask & MATCH_DST_PORT))) return 0;
    if ((rule->match_mask & MATCH_PROTO) && ((pkt->proto == rule->proto) == !!(rule->invert_mask & MATCH_PROTO))) return 0;
    if ((rule->match_mask & MATCH_DIRECTION) && ((direction == rule->direction) == !!(rule->invert_mask & MATCH_DIRECTION))) return 0;
    if ((rule->match_mask & MATCH_TTL) && ((pkt->ttl == rule->ttl) == !!(rule->invert_mask & MATCH_TTL))) return 0;
    if ((rule->match_mask & MATCH_TCP_FLAGS) && (((pkt->tcp_flags & rule->tcp_flags_mask) == rule->tcp_flags) == !!(rule->invert_mask & MATCH_TCP_FLAGS))) return 0;

    if ((rule->match_mask & MATCH_LOOPBACK) && pkt->is_lo != rule->loopback) return 0;

    return 1;
}

/*
 * Per-rule matching lives in global functions: the verifier checks each once
 * instead of once per loop iteration and path, which keeps the 64-rule loops
 * within the complexity limit of older kernels.  Global functions only take
 * scalars, so the parsed packet travels through a per-CPU scratch map.
 */
struct match_scratch {
    struct parsed_packet pkt;
    __u32 direction;
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct match_scratch);
} scratch_map SEC(".maps");

/* Returns the rule's match_mask if rule idx matches, 0 if not, -1 past the end. */
__attribute__((noinline)) int match_rule_v4(__u32 idx)
{
    __u32 k0 = 0;
    struct match_scratch *s = bpf_map_lookup_elem(&scratch_map, &k0);
    struct filter_rule *rule = bpf_map_lookup_elem(&filter_rules, &idx);
    if (!s || !rule || rule->match_mask == 0)
        return -1;
    return matches_rule_ipv4(&s->pkt, rule, (__u8)s->direction) ? rule->match_mask : 0;
}

__attribute__((noinline)) int match_rule_v6(__u32 idx)
{
    __u32 k0 = 0;
    struct match_scratch *s = bpf_map_lookup_elem(&scratch_map, &k0);
    struct filter_rule_ipv6 *rule = bpf_map_lookup_elem(&filter_rules_ipv6, &idx);
    if (!s || !rule || rule->match_mask == 0)
        return -1;
    return matches_rule_ipv6(&s->pkt, rule, (__u8)s->direction) ? rule->match_mask : 0;
}

/*
 * Is an ingress packet going to be forwarded rather than delivered locally?
 * Only consulted when IP forwarding is enabled (CFG_F_FWD_CHECK).
 */
static __always_inline int is_forwarded(struct __sk_buff *skb, struct parsed_packet *pkt) {
    struct bpf_fib_lookup params = {0};
    params.ifindex = skb->ifindex;
    params.l4_protocol = pkt->proto;
    params.sport = bpf_htons(pkt->src_port);
    params.dport = bpf_htons(pkt->dst_port);
    if (pkt->ver == 4) {
        params.family = AF_INET;
        params.ipv4_src = bpf_htonl(pkt->src_ip);
        params.ipv4_dst = bpf_htonl(pkt->dst_ip);
    } else {
        params.family = AF_INET6;
        __builtin_memcpy(params.ipv6_src, pkt->src_ip6, 16);
        __builtin_memcpy(params.ipv6_dst, pkt->dst_ip6, 16);
    }
    long ret = bpf_fib_lookup(skb, &params, sizeof(params), 0);
    return ret == BPF_FIB_LKUP_RET_SUCCESS || ret == BPF_FIB_LKUP_RET_NO_NEIGH ||
           ret == BPF_FIB_LKUP_RET_FRAG_NEEDED;
}

/*
 * Copy the packet into the ring buffer.  bpf_ringbuf_reserve() needs a
 * constant size, so records come in three size classes.
 */
#define EMIT_CLASS(SIZE)                                                            \
    do {                                                                            \
        struct divert_packet_buffer *buf =                                         \
            bpf_ringbuf_reserve(&pcap_ringbuf, sizeof(struct divert_pkt_header) + (SIZE), 0); \
        if (!buf) {                                                                 \
            increment_stat(STAT_RINGBUF_FULL);                                      \
            return -1;                                                              \
        }                                                                           \
        /* len is in [1, SIZE]; prove it with instructions no compiler can      \
         * rewrite and every verifier tracks: n = ((len - 1) & (SIZE - 1)) + 1. */ \
        __u64 n = len;                                                              \
        asm volatile("%[n] += -1\n\t%[n] &= %[m]\n\t%[n] += 1"                      \
                     : [n] "+r"(n) : [m] "i"((SIZE) - 1));                          \
        if (bpf_skb_load_bytes(skb, 0, buf->data, n) < 0) {                         \
            bpf_ringbuf_discard(buf, 0);                                            \
            increment_stat(STAT_PARSING_ERR);                                       \
            return -1;                                                              \
        }                                                                           \
        buf->header.pkt_len = meta->len;                                            \
        buf->header.ifindex = meta->ifindex;                                        \
        buf->header.direction = direction;                                          \
        buf->header.l2_len = pkt->l2_len;                                           \
        buf->header.cap_len = (__u32)n;                                             \
        buf->header.timestamp = bpf_ktime_get_ns();                                 \
        buf->header.ingress_ifindex = meta->ingress_ifindex;                        \
        buf->header.gso_size = (__u16)meta->gso_size;                               \
        buf->header.gso_segs = (__u16)meta->gso_segs;                               \
        buf->header.flags = flags;                                                  \
        buf->header.reserved = 0;                                                   \
        buf->header.reserved2 = 0;                                                  \
        bpf_ringbuf_submit(buf, 0);                                                 \
        return 0;                                                                   \
    } while (0)

/* __sk_buff fields copied into the record; read up front because the
 * verifier only allows context loads at constant offsets. */
struct skb_meta {
    __u32 len;
    __u32 ifindex;
    __u32 ingress_ifindex;
    __u32 gso_size;
    __u32 gso_segs;
};

static __always_inline int emit_packet(struct __sk_buff *skb, struct parsed_packet *pkt,
                                       __u16 direction, __u16 flags, __u32 len) {
    struct skb_meta m;
    struct skb_meta *meta = &m;
    m.len = skb->len;
    m.ifindex = skb->ifindex;
    m.ingress_ifindex = skb->ingress_ifindex;
    m.gso_size = skb->gso_size;
    m.gso_segs = skb->gso_segs;
    barrier_var(meta);

    if (len <= 2048) {
        EMIT_CLASS(2048);
    } else if (len <= 16384) {
        EMIT_CLASS(16384);
    } else {
        EMIT_CLASS(DIVERT_MAX_PACKET);
    }
}

static __always_inline int process_packet(struct __sk_buff *skb, __u16 direction) {
    __u32 key = 0;
    struct divert_config *cfg = bpf_map_lookup_elem(&config_map, &key);
    if (!cfg || (cfg->flags & CFG_F_SHUTDOWN)) return TC_ACT_UNSPEC;

    /* Fail open when the owning process stopped refreshing its heartbeat. */
    __u64 hb_timeout = cfg->heartbeat_timeout_ns;
    if (hb_timeout && bpf_ktime_get_ns() - cfg->heartbeat_ns > hb_timeout) {
        increment_stat(STAT_OWNER_GONE);
        return TC_ACT_UNSPEC;
    }

    __u32 my_prio = cfg->priority;
    __u32 prevent_mark = cfg->loop_prevention_mark ? cfg->loop_prevention_mark : LOOP_PREVENTION_MARK;
    __u16 flags = 0;

    if ((skb->mark & 0xFFFF0000) == (prevent_mark & 0xFFFF0000)) {
        __u16 inject_prio = skb->mark & 0xFFFF;
        // Handles with the same or a higher priority (lower or equal TC
        // priority) than the injector ignore the packet; lower-priority
        // handles see it as an impostor.
        if (my_prio <= inject_prio) return TC_ACT_UNSPEC;
        flags |= PKT_F_IMPOSTOR;
    }

    if ((skb->mark & 0xFFFF0000) == REDIRECT_MARK_MASK) {
        return TC_ACT_UNSPEC;
    }

    int is_lo = (skb->ifindex == cfg->lo_ifindex);
    // Loopback traffic crosses lo egress and then lo ingress; like WinDivert,
    // only report it once, as outbound.
    if (is_lo && direction == DIR_INGRESS) return TC_ACT_UNSPEC;
    if (is_lo && (cfg->flags & CFG_F_SKIP_LO)) return TC_ACT_UNSPEC;
    if (is_lo) flags |= PKT_F_LOOPBACK;

    if (direction == DIR_INGRESS && (cfg->flags & CFG_F_NO_INBOUND)) return TC_ACT_UNSPEC;
    if (direction == DIR_EGRESS && (cfg->flags & CFG_F_NO_OUTBOUND)) return TC_ACT_UNSPEC;

    int forward_layer = !!(cfg->flags & CFG_F_FORWARD);
    if (direction == DIR_EGRESS) {
        int forwarded = !is_lo && skb->ingress_ifindex != 0;
        if (forwarded != forward_layer) return TC_ACT_UNSPEC;
        if (forwarded) flags |= PKT_F_FORWARD;
    } else if (forward_layer) {
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
        // Not IPv4/IPv6 (ARP, LLDP, ...): WinDivert never sees these.
        return TC_ACT_UNSPEC;
    }
    pkt.is_lo = is_lo;

    if (pkt.fragment) {
        flags |= PKT_F_FRAGMENT;
        if (direction == DIR_INGRESS && !(cfg->flags & CFG_F_FRAGMENTS)) return TC_ACT_UNSPEC;
    }

    if (direction == DIR_INGRESS && (cfg->flags & CFG_F_FWD_CHECK) && is_forwarded(skb, &pkt)) {
        return TC_ACT_UNSPEC;
    }

    int matched = 0;
    __u16 match_mask = 0;

    if (pkt.fragment) {
        /*
         * Fragments carry no (or partial) transport headers, so the rules
         * cannot judge them.  Hand them to user space, which evaluates the
         * exact filter, whenever the filter can match anything at all.
         */
        __u32 k = 0;
        __u16 mm = 0;
        if (pkt.ver == 4) {
            struct filter_rule *rule = bpf_map_lookup_elem(&filter_rules, &k);
            if (rule) mm = rule->match_mask;
        } else {
            struct filter_rule_ipv6 *rule = bpf_map_lookup_elem(&filter_rules_ipv6, &k);
            if (rule) mm = rule->match_mask;
        }
        if (!(mm & MATCH_ENABLED) || (mm & MATCH_FALSE)) return TC_ACT_UNSPEC;
        matched = 1;
        match_mask = mm & ~MATCH_DROP;
    } else {
        __u32 k0 = 0;
        struct match_scratch *scratch = bpf_map_lookup_elem(&scratch_map, &k0);
        if (!scratch) return TC_ACT_UNSPEC;
        __builtin_memcpy(&scratch->pkt, &pkt, sizeof(pkt));
        scratch->direction = direction;
        for (__u32 i = 0; i < MAX_RULES; i++) {
            int m = (pkt.ver == 4) ? match_rule_v4(i) : match_rule_v6(i);
            if (m < 0) break;
            if (m > 0) {
                matched = 1;
                match_mask = (__u16)m;
                break;
            }
        }
    }

    if (!matched) return TC_ACT_UNSPEC;

    if (match_mask & MATCH_DROP) {
        increment_stat(STAT_DROPPED);
        return TC_ACT_SHOT;
    }

    int sniff = !!(match_mask & MATCH_SNIFF);
    __u32 len = skb->len;
    __u32 snap = cfg->snaplen ? cfg->snaplen : DIVERT_MAX_PACKET;
    if (snap > DIVERT_MAX_PACKET) snap = DIVERT_MAX_PACKET;
    if (len > snap) {
        // A diverted packet must be copied whole or it cannot be re-injected.
        if (!sniff) {
            increment_stat(STAT_TOO_BIG);
            return TC_ACT_UNSPEC;
        }
        len = snap;
    }
    if (sniff) flags |= PKT_F_SNIFFED;

    if (emit_packet(skb, &pkt, direction, flags, len) < 0) {
        return TC_ACT_UNSPEC;
    }

    if (sniff) {
        increment_stat(STAT_SNIFFED);
        return TC_ACT_UNSPEC;
    }

    increment_stat(STAT_DIVERTED);
    return TC_ACT_STOLEN;
}

SEC("classifier")
int tc_divert_ingress(struct __sk_buff *skb) {
    __u32 mark = skb->mark;
    if ((mark & 0xFFFF0000) == REDIRECT_MARK_MASK) {
        /* Inbound injection sent through lo: hand it to the target.  The
         * redirect clears skb->priority, so move the injector's priority
         * into the mark first. */
        __u32 target_ifindex = mark & 0xFFFF;
        __u32 prio = skb->priority;
        prio = ((prio & 0xFFFF0000) == REDIRECT_PRIO_MAGIC) ? (prio & 0xFFFF) : 0;
        skb->mark = REDIRECTED_MARK | prio;
        skb->priority = 0;
        return bpf_redirect(target_ifindex, BPF_F_INGRESS);
    }
    if ((mark & 0xFFFF0000) == REDIRECTED_MARK) {
        /* Arrived on the target: the injector and higher-priority handles
         * must skip it, lower-priority ones see an impostor. */
        skb->mark = LOOP_PREVENTION_MARK | (mark & 0xFFFF);
        bpf_skb_change_type(skb, PACKET_HOST);
    }
    return process_packet(skb, DIR_INGRESS);
}

SEC("classifier")
int tc_divert_egress(struct __sk_buff *skb) {
    return process_packet(skb, DIR_EGRESS);
}

char _license[] SEC("license") = "GPL";
