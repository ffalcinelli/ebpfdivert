// SPDX-License-Identifier: GPL-2.0-or-later OR LGPL-3.0-or-later
/*
 * ebpfdivert_events.bpf.c - the FLOW and SOCKET layers.
 *
 * Programs attach to the root cgroup v2 (through bpf_links, so they go away
 * with the owning process) and report socket events to user space, which
 * evaluates the exact WinDivert filter:
 *
 *   SOCKET: BIND (post_bind), CONNECT (connect), LISTEN (sockops), ACCEPT
 *           (sockops, passive established), CLOSE (sock_release).  BIND and
 *           CONNECT can be refused when the handle is not a sniffer.
 *   FLOW:   ESTABLISHED / DELETED for TCP (sockops state changes) and UDP
 *           (first packet of a 5-tuple, seen by cgroup_skb; DELETED is
 *           synthesized in user space when the socket is released).
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "ebpfdivert_shared.h"

#define AF_INET     2
#define AF_INET6    10
#define IPPROTO_TCP 6
#define IPPROTO_UDP 17
#define TCP_CLOSE   7

/* Set by user space before load: whether bpf_get_current_pid_tgid() is
 * allowed in cgroup socket programs on this kernel. */
const volatile __u32 have_pid_helper = 0;

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);
} event_ringbuf SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct event_config);
} event_config_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, EVENT_RULES_MAX);
    __type(key, __u32);
    __type(value, struct event_rule);
} event_rules SEC(".maps");

/*
 * Per-socket state: the owning process, recorded at creation (cloned on
 * accept), and the last known endpoints.  sock_release programs cannot read
 * the socket's addresses, so CLOSE events are built from here.
 */
struct sk_info {
    __u32 pid;
    __u16 local_port;
    __u16 remote_port;
    __u8  family;
    __u8  pad[3];
    __u8  local_addr[16];
    __u8  remote_addr[16];
};

struct {
    __uint(type, BPF_MAP_TYPE_SK_STORAGE);
    __uint(map_flags, BPF_F_NO_PREALLOC | BPF_F_CLONE);
    __type(key, int);
    __type(value, struct sk_info);
} sk_info_map SEC(".maps");

/* UDP 5-tuples already reported as established. */
struct udp_flow_key {
    __u64 cookie;
    __u8  remote_addr[16];
    __u16 remote_port;
    __u16 local_port;
    __u32 pad;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, struct udp_flow_key);
    __type(value, __u8);
} udp_flows SEC(".maps");

static __always_inline struct event_config *live_config(void)
{
    __u32 key = 0;
    struct event_config *cfg = bpf_map_lookup_elem(&event_config_map, &key);
    if (!cfg || (cfg->flags & EVCFG_F_SHUTDOWN))
        return NULL;
    if (cfg->heartbeat_timeout_ns &&
        bpf_ktime_get_ns() - cfg->heartbeat_ns > cfg->heartbeat_timeout_ns)
        return NULL;
    return cfg;
}

static __always_inline void v4_mapped(__u8 *dst, __u32 addr_be)
{
    __builtin_memset(dst, 0, 10);
    dst[10] = 0xFF;
    dst[11] = 0xFF;
    __builtin_memcpy(dst + 12, &addr_be, 4);
}

/*
 * Context arrays must be read with constant-offset loads from the context
 * pointer itself: the barrier stops clang from hoisting "ctx + offset".
 */
#define CTX_IP6_READ(w, ctx, field)         \
    do {                                    \
        (w)[0] = (ctx)->field[0];           \
        barrier_var(ctx);                   \
        (w)[1] = (ctx)->field[1];           \
        barrier_var(ctx);                   \
        (w)[2] = (ctx)->field[2];           \
        barrier_var(ctx);                   \
        (w)[3] = (ctx)->field[3];           \
        barrier_var(ctx);                   \
    } while (0)

static __always_inline void v6_copy(__u8 *dst, const __u32 *words_be)
{
    __u32 w0 = words_be[0], w1 = words_be[1], w2 = words_be[2], w3 = words_be[3];
    __builtin_memcpy(dst, &w0, 4);
    __builtin_memcpy(dst + 4, &w1, 4);
    __builtin_memcpy(dst + 8, &w2, 4);
    __builtin_memcpy(dst + 12, &w3, 4);
}

static __always_inline int is_loopback(const __u8 *a)
{
    /* 127/8 (as ::ffff:127.x.y.z) or ::1 */
    __u64 hi, lo;
    __builtin_memcpy(&hi, a, 8);
    __builtin_memcpy(&lo, a + 8, 8);
    if (hi == 0 && a[8] == 0 && a[9] == 0 && a[10] == 0xFF && a[11] == 0xFF)
        return a[12] == 127;
    return hi == 0 && lo == bpf_cpu_to_be64(1);
}

static __always_inline int addr_match(const __u8 *a, const __u8 *ip, const __u8 *mask)
{
    __u64 a0, a1, i0, i1, m0, m1;
    __builtin_memcpy(&a0, a, 8);
    __builtin_memcpy(&a1, a + 8, 8);
    __builtin_memcpy(&i0, ip, 8);
    __builtin_memcpy(&i1, ip + 8, 8);
    __builtin_memcpy(&m0, mask, 8);
    __builtin_memcpy(&m1, mask + 8, 8);
    return ((a0 ^ i0) & m0) == 0 && ((a1 ^ i1) & m1) == 0;
}

/* Does an exactly lowered SOCKET rule match the event? */
static __always_inline int rule_match(const struct event_rule *r, const struct divert_event *e)
{
    __u32 mm = r->match_mask, inv = r->invert_mask;
    if (!(mm & EVM_ENABLED))
        return 0;
    if ((mm & EVM_EVENT) && !(r->event_mask & (1 << e->event)))
        return 0;
    if ((mm & EVM_FAMILY) && e->family != r->family)
        return 0;
    if ((mm & EVM_PROTO) && ((e->protocol == r->proto) == !!(inv & EVM_PROTO)))
        return 0;
    if ((mm & EVM_LPORT) && ((e->local_port >= r->lport_lo && e->local_port <= r->lport_hi) ==
                             !!(inv & EVM_LPORT)))
        return 0;
    if ((mm & EVM_RPORT) && ((e->remote_port >= r->rport_lo && e->remote_port <= r->rport_hi) ==
                             !!(inv & EVM_RPORT)))
        return 0;
    if ((mm & EVM_PID) && ((e->pid >= r->pid_lo && e->pid <= r->pid_hi) == !!(inv & EVM_PID)))
        return 0;
    if ((mm & EVM_LADDR) && (addr_match(e->local_addr, r->laddr, r->lmask) == !!(inv & EVM_LADDR)))
        return 0;
    if ((mm & EVM_RADDR) && (addr_match(e->remote_addr, r->raddr, r->rmask) == !!(inv & EVM_RADDR)))
        return 0;
    if ((mm & EVM_LOOPBACK) && (is_loopback(e->remote_addr) || is_loopback(e->local_addr)) != r->loopback)
        return 0;
    return 1;
}

static __always_inline int should_block(struct event_config *cfg, const struct divert_event *e)
{
    if (!(cfg->flags & EVCFG_F_BLOCK))
        return 0;
    for (__u32 i = 0; i < EVENT_RULES_MAX; i++) {
        __u32 k = i;
        struct event_rule *r = bpf_map_lookup_elem(&event_rules, &k);
        if (!r || !(r->match_mask & EVM_ENABLED))
            break;
        if (rule_match(r, e))
            return 1;
    }
    return 0;
}

static __always_inline void submit(const struct divert_event *e)
{
    struct divert_event *out = bpf_ringbuf_reserve(&event_ringbuf, sizeof(*out), 0);
    if (!out)
        return;
    __builtin_memcpy(out, e, sizeof(*out));
    bpf_ringbuf_submit(out, 0);
}

static __always_inline __u32 current_pid(void)
{
    if (have_pid_helper)
        return (__u32)(bpf_get_current_pid_tgid() >> 32);
    return 0;
}

static __always_inline __u32 sk_pid(struct bpf_sock *sk)
{
    struct sk_info *info;
    if (!sk)
        return 0;
    info = bpf_sk_storage_get(&sk_info_map, sk, 0, 0);
    return info ? info->pid : 0;
}

/* Record an event's endpoints on the socket (for CLOSE). */
static __always_inline void remember(struct bpf_sock *sk, const struct divert_event *e)
{
    struct sk_info *info;
    if (!sk)
        return;
    info = bpf_sk_storage_get(&sk_info_map, sk, 0, BPF_SK_STORAGE_GET_F_CREATE);
    if (!info)
        return;
    info->family = e->family;
    if (e->local_port)
        info->local_port = e->local_port;
    if (e->remote_port) {
        info->remote_port = e->remote_port;
        __builtin_memcpy(info->remote_addr, e->remote_addr, 16);
    }
    __builtin_memcpy(info->local_addr, e->local_addr, 16);
}

/****************************************************************************/
/* Socket ownership                                                         */
/****************************************************************************/

SEC("cgroup/sock_create")
int ev_sock_create(struct bpf_sock *sk)
{
    struct sk_info *info = bpf_sk_storage_get(&sk_info_map, sk, 0, BPF_SK_STORAGE_GET_F_CREATE);
    if (info)
        info->pid = current_pid();
    return 1;
}

/****************************************************************************/
/* SOCKET: bind, connect, close                                             */
/****************************************************************************/

static __always_inline int on_bind(struct bpf_sock *sk, int v6)
{
    struct event_config *cfg = live_config();
    struct divert_event e = {};
    if (!cfg || !(cfg->flags & EVCFG_F_SOCKET))
        return 1;
    e.timestamp = bpf_ktime_get_ns();
    e.endpoint_id = bpf_get_socket_cookie(sk);
    e.pid = current_pid();
    e.event = DIVERT_EVENT_SOCKET_BIND;
    e.protocol = (__u8)sk->protocol;
    e.family = v6 ? 6 : 4;
    e.local_port = (__u16)sk->src_port;
    if (v6) {
        __u32 w[4];
        CTX_IP6_READ(w, sk, src_ip6);
        v6_copy(e.local_addr, w);
    } else {
        v4_mapped(e.local_addr, sk->src_ip4);
    }
    if (should_block(cfg, &e)) {
        e.flags |= EVF_BLOCKED;
        submit(&e);
        return 0;
    }
    remember(sk, &e);
    submit(&e);
    return 1;
}

SEC("cgroup/post_bind4")
int ev_post_bind4(struct bpf_sock *sk)
{
    return on_bind(sk, 0);
}

SEC("cgroup/post_bind6")
int ev_post_bind6(struct bpf_sock *sk)
{
    return on_bind(sk, 1);
}

static __always_inline int on_connect(struct bpf_sock_addr *ctx, int v6)
{
    struct event_config *cfg = live_config();
    struct divert_event e = {};
    struct bpf_sock *sk;
    if (!cfg || !(cfg->flags & EVCFG_F_SOCKET))
        return 1;
    e.timestamp = bpf_ktime_get_ns();
    e.endpoint_id = bpf_get_socket_cookie(ctx);
    e.pid = current_pid();
    e.event = DIVERT_EVENT_SOCKET_CONNECT;
    e.protocol = (__u8)ctx->protocol;
    e.family = v6 ? 6 : 4;
    e.remote_port = bpf_ntohs((__u16)ctx->user_port);
    if (v6) {
        __u32 w[4];
        CTX_IP6_READ(w, ctx, user_ip6);
        v6_copy(e.remote_addr, w);
    } else {
        v4_mapped(e.remote_addr, ctx->user_ip4);
    }
    sk = ctx->sk;
    if (sk) {
        /* The local endpoint is only known if the socket was bound. */
        struct sk_info *info = bpf_sk_storage_get(&sk_info_map, sk, 0, 0);
        if (info && info->family == e.family) {
            e.local_port = info->local_port;
            __builtin_memcpy(e.local_addr, info->local_addr, 16);
        }
    }
    if (!v6 && !e.local_addr[10])
        v4_mapped(e.local_addr, 0);
    if (should_block(cfg, &e)) {
        e.flags |= EVF_BLOCKED;
        submit(&e);
        return 0;
    }
    remember(sk, &e);
    submit(&e);
    return 1;
}

SEC("cgroup/connect4")
int ev_connect4(struct bpf_sock_addr *ctx)
{
    return on_connect(ctx, 0);
}

SEC("cgroup/connect6")
int ev_connect6(struct bpf_sock_addr *ctx)
{
    return on_connect(ctx, 1);
}

SEC("cgroup/sock_release")
int ev_sock_release(struct bpf_sock *sk)
{
    struct event_config *cfg = live_config();
    struct divert_event e = {};
    struct sk_info *info;
    if (!cfg)
        return 1;
    if (sk->family != AF_INET && sk->family != AF_INET6)
        return 1;
    e.timestamp = bpf_ktime_get_ns();
    e.endpoint_id = bpf_get_socket_cookie(sk);
    e.protocol = (__u8)sk->protocol;
    e.family = (sk->family == AF_INET6) ? 6 : 4;
    info = bpf_sk_storage_get(&sk_info_map, sk, 0, 0);
    if (info) {
        e.pid = info->pid;
        e.local_port = info->local_port;
        e.remote_port = info->remote_port;
        __builtin_memcpy(e.local_addr, info->local_addr, 16);
        __builtin_memcpy(e.remote_addr, info->remote_addr, 16);
    }
    if (e.family == 4 && !e.local_addr[10])
        v4_mapped(e.local_addr, 0);
    if (e.family == 4 && !e.remote_addr[10])
        v4_mapped(e.remote_addr, 0);
    if (cfg->flags & EVCFG_F_SOCKET) {
        e.event = DIVERT_EVENT_SOCKET_CLOSE;
        submit(&e);
    } else if (e.protocol == IPPROTO_UDP) {
        /* FLOW: user space turns this into DELETED events for the socket's
         * UDP flows. */
        e.event = DIVERT_EVENT_FLOW_DELETED;
        e.flags |= EVF_UDP_RELEASE;
        submit(&e);
    }
    return 1;
}

/****************************************************************************/
/* TCP state: LISTEN, ACCEPT, FLOW ESTABLISHED/DELETED                      */
/****************************************************************************/

static __always_inline void fill_sockops(struct divert_event *e, struct bpf_sock_ops *skops)
{
    int v6 = (skops->family == AF_INET6);
    e->timestamp = bpf_ktime_get_ns();
    e->endpoint_id = bpf_get_socket_cookie(skops);
    e->protocol = IPPROTO_TCP;
    e->family = v6 ? 6 : 4;
    e->local_port = (__u16)skops->local_port;
    e->remote_port = (__u16)bpf_ntohl(skops->remote_port);
    if (v6) {
        __u32 l[4], r[4];
        CTX_IP6_READ(l, skops, local_ip6);
        CTX_IP6_READ(r, skops, remote_ip6);
        v6_copy(e->local_addr, l);
        v6_copy(e->remote_addr, r);
    } else {
        v4_mapped(e->local_addr, skops->local_ip4);
        v4_mapped(e->remote_addr, skops->remote_ip4);
    }
    if (skops->sk) {
        e->pid = sk_pid(skops->sk);
        remember(skops->sk, e);
    }
}

SEC("sockops")
int ev_sockops(struct bpf_sock_ops *skops)
{
    struct event_config *cfg = live_config();
    struct divert_event e = {};
    __u32 op = skops->op;
    int socket_layer;

    if (!cfg || (skops->family != AF_INET && skops->family != AF_INET6))
        return 1;
    socket_layer = !!(cfg->flags & EVCFG_F_SOCKET);

    switch (op) {
    case BPF_SOCK_OPS_TCP_LISTEN_CB:
        if (!socket_layer)
            return 1;
        fill_sockops(&e, skops);
        e.event = DIVERT_EVENT_SOCKET_LISTEN;
        submit(&e);
        break;
    case BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB:
    case BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB:
        fill_sockops(&e, skops);
        if (socket_layer) {
            if (op != BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB)
                return 1;
            e.event = DIVERT_EVENT_SOCKET_ACCEPT;
        } else {
            e.event = DIVERT_EVENT_FLOW_ESTABLISHED;
            /* Ask for state changes to report the flow's end. */
            bpf_sock_ops_cb_flags_set(skops, skops->bpf_sock_ops_cb_flags | BPF_SOCK_OPS_STATE_CB_FLAG);
        }
        submit(&e);
        break;
    case BPF_SOCK_OPS_STATE_CB:
        if (socket_layer || skops->args[1] != TCP_CLOSE)
            return 1;
        fill_sockops(&e, skops);
        e.event = DIVERT_EVENT_FLOW_DELETED;
        submit(&e);
        break;
    default:
        break;
    }
    return 1;
}

/****************************************************************************/
/* UDP flows                                                                */
/****************************************************************************/

static __always_inline int udp_flow(struct __sk_buff *skb, int egress)
{
    struct event_config *cfg = live_config();
    struct divert_event e = {};
    struct udp_flow_key key = {};
    struct bpf_sock *sk;
    __u8 ver;
    __u16 ports[2];
    __u32 thoff;

    if (!cfg || (cfg->flags & EVCFG_F_SOCKET))
        return 1;
    sk = skb->sk;
    if (!sk)
        return 1;
    sk = bpf_sk_fullsock(sk);
    if (!sk || sk->protocol != IPPROTO_UDP)
        return 1;

    if (bpf_skb_load_bytes(skb, 0, &ver, 1) < 0)
        return 1;
    ver >>= 4;
    if (ver == 4) {
        struct iphdr ip;
        if (bpf_skb_load_bytes(skb, 0, &ip, sizeof(ip)) < 0 || ip.protocol != IPPROTO_UDP ||
            (bpf_ntohs(ip.frag_off) & 0x1FFF))
            return 1;
        thoff = ip.ihl * 4;
        e.family = 4;
        v4_mapped(e.local_addr, egress ? ip.saddr : ip.daddr);
        v4_mapped(e.remote_addr, egress ? ip.daddr : ip.saddr);
    } else if (ver == 6) {
        struct ipv6hdr ip6;
        if (bpf_skb_load_bytes(skb, 0, &ip6, sizeof(ip6)) < 0 || ip6.nexthdr != IPPROTO_UDP)
            return 1;
        thoff = sizeof(ip6);
        e.family = 6;
        __builtin_memcpy(e.local_addr, egress ? &ip6.saddr : &ip6.daddr, 16);
        __builtin_memcpy(e.remote_addr, egress ? &ip6.daddr : &ip6.saddr, 16);
    } else {
        return 1;
    }
    if (bpf_skb_load_bytes(skb, thoff & 0xFF, ports, sizeof(ports)) < 0)
        return 1;
    e.local_port = bpf_ntohs(egress ? ports[0] : ports[1]);
    e.remote_port = bpf_ntohs(egress ? ports[1] : ports[0]);

    e.endpoint_id = bpf_get_socket_cookie(skb);
    key.cookie = e.endpoint_id;
    __builtin_memcpy(key.remote_addr, e.remote_addr, 16);
    key.remote_port = e.remote_port;
    key.local_port = e.local_port;
    if (bpf_map_lookup_elem(&udp_flows, &key))
        return 1;
    {
        __u8 one = 1;
        bpf_map_update_elem(&udp_flows, &key, &one, BPF_ANY);
    }
    e.timestamp = bpf_ktime_get_ns();
    e.pid = sk_pid(sk);
    e.protocol = IPPROTO_UDP;
    remember(sk, &e);
    e.event = DIVERT_EVENT_FLOW_ESTABLISHED;
    submit(&e);
    return 1;
}

SEC("cgroup_skb/egress")
int ev_skb_egress(struct __sk_buff *skb)
{
    return udp_flow(skb, 1);
}

SEC("cgroup_skb/ingress")
int ev_skb_ingress(struct __sk_buff *skb)
{
    return udp_flow(skb, 0);
}

char _license[] SEC("license") = "GPL";
