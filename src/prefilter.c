// SPDX-License-Identifier: GPL-2.0-or-later OR LGPL-3.0-or-later
/*
 * prefilter.c - lower a compiled WinDivert filter to kernel filter rules.
 *
 * The BPF program can only evaluate a small DNF of conjunctive rules
 * (struct filter_rule / filter_rule_ipv6).  This file walks the compiled
 * WINDIVERT_FILTER decision DAG, enumerates every path that reaches ACCEPT
 * and turns each path into one or more rules ("cubes").  Anything the
 * kernel cannot express is dropped from the cube ("widened"), which keeps
 * the rules a superset of the filter: user space then evaluates the exact
 * filter on each captured packet and re-injects the ones that don't match.
 * When nothing was widened the result is flagged exact and user space
 * skips evaluation.
 */
#include <errno.h>
#include <stdlib.h>

#define WINDIVERTEXPORT extern __attribute__((visibility("hidden")))
#include "windivert.h"
#include "windivert_device.h"
#include "ebpfdivert_shared.h"
#include "prefilter.h"
#include "wd.h"

#define PF_MAX_EXCL     4
#define PF_MAX_STATES   65536
#define PF_MAX_CUBES    256

/* An inclusive interval on an unsigned value, minus a few excluded points. */
struct pf_range
{
    UINT32 lo, hi;
    UINT32 excl[PF_MAX_EXCL];
    UINT nexcl;
};

/* 128-bit address range, host order, word 0 = least significant. */
struct pf_addr
{
    UINT32 lo[4], hi[4];
    UINT32 excl[4];
    int has_excl;
};

struct pf_cube
{
    int exact;
    int ver;                    /* 0 = any, 4, 6 */
    int dir;                    /* 0 = any, 1 = inbound, 2 = outbound */
    int loopback;               /* -1 = any, 0, 1 */
    struct pf_range proto;
    struct pf_range sport;      /* tcp/udp source port, icmp type */
    struct pf_range dport;      /* tcp/udp destination port, icmp code */
    struct pf_range ttl;
    struct pf_addr src, dst;
    UINT8 tcp_flags, tcp_mask;
    /* Event layers (FLOW, SOCKET) only. */
    struct pf_range event;
    struct pf_range pid;
};

struct pf_ctx
{
    const WINDIVERT_FILTER *obj;
    UINT len;
    struct pf_cube cubes[PF_MAX_CUBES];
    UINT ncubes;
    UINT states;
    int overflow;
    int event_mode;             /* FLOW/SOCKET filters */
};

static void range_full(struct pf_range *r, UINT32 max)
{
    r->lo = 0;
    r->hi = max;
    r->nexcl = 0;
}

static int range_is_full(const struct pf_range *r, UINT32 max)
{
    return r->lo == 0 && r->hi == max && r->nexcl == 0;
}

static int range_contains(const struct pf_range *r, UINT32 v)
{
    UINT i;
    if (v < r->lo || v > r->hi)
    {
        return 0;
    }
    for (i = 0; i < r->nexcl; i++)
    {
        if (r->excl[i] == v)
        {
            return 0;
        }
    }
    return 1;
}

/* Remove excluded points that are outside the interval or on its edge. */
static void range_normalize(struct pf_range *r)
{
    UINT i, j;
    int changed = 1;
    while (changed)
    {
        changed = 0;
        for (i = 0; i < r->nexcl; i++)
        {
            UINT32 x = r->excl[i];
            int drop = 0;
            if (x < r->lo || x > r->hi)
            {
                drop = 1;
            }
            else if (r->lo == r->hi)
            {
                /* The only remaining value is excluded: empty. */
                r->lo = 1;
                r->hi = 0;
                r->nexcl = 0;
                return;
            }
            else if (x == r->lo)
            {
                r->lo++;
                drop = changed = 1;
            }
            else if (x == r->hi)
            {
                r->hi--;
                drop = changed = 1;
            }
            if (drop)
            {
                for (j = i; j + 1 < r->nexcl; j++)
                {
                    r->excl[j] = r->excl[j + 1];
                }
                r->nexcl--;
                i--;
            }
        }
    }
}

/*
 * Intersect with "v <test> arg".  Returns 0 if the result is empty.
 * *exact is cleared when the constraint had to be widened.
 */
static int range_apply(struct pf_range *r, UINT test, UINT32 arg, UINT32 max,
    int *exact)
{
    UINT32 lo = 0, hi = max;
    if (arg > max)
    {
        switch (test)
        {
            case WINDIVERT_FILTER_TEST_EQ:
            case WINDIVERT_FILTER_TEST_GT:
            case WINDIVERT_FILTER_TEST_GEQ:
                return 0;
            default:
                return 1;       /* always true */
        }
    }
    switch (test)
    {
        case WINDIVERT_FILTER_TEST_EQ:
            lo = hi = arg;
            break;
        case WINDIVERT_FILTER_TEST_NEQ:
            if (!range_contains(r, arg))
            {
                return 1;
            }
            if (r->nexcl == PF_MAX_EXCL)
            {
                *exact = 0;
                return 1;
            }
            r->excl[r->nexcl++] = arg;
            range_normalize(r);
            return r->lo <= r->hi;
        case WINDIVERT_FILTER_TEST_LT:
            if (arg == 0)
            {
                return 0;
            }
            hi = arg - 1;
            break;
        case WINDIVERT_FILTER_TEST_LEQ:
            hi = arg;
            break;
        case WINDIVERT_FILTER_TEST_GT:
            if (arg == max)
            {
                return 0;
            }
            lo = arg + 1;
            break;
        case WINDIVERT_FILTER_TEST_GEQ:
            lo = arg;
            break;
        default:
            *exact = 0;
            return 1;
    }
    if (lo > r->lo)
    {
        r->lo = lo;
    }
    if (hi < r->hi)
    {
        r->hi = hi;
    }
    if (r->lo > r->hi)
    {
        return 0;
    }
    range_normalize(r);
    return r->lo <= r->hi;
}

static UINT negate_test(UINT test)
{
    switch (test)
    {
        case WINDIVERT_FILTER_TEST_EQ:  return WINDIVERT_FILTER_TEST_NEQ;
        case WINDIVERT_FILTER_TEST_NEQ: return WINDIVERT_FILTER_TEST_EQ;
        case WINDIVERT_FILTER_TEST_LT:  return WINDIVERT_FILTER_TEST_GEQ;
        case WINDIVERT_FILTER_TEST_LEQ: return WINDIVERT_FILTER_TEST_GT;
        case WINDIVERT_FILTER_TEST_GT:  return WINDIVERT_FILTER_TEST_LEQ;
        case WINDIVERT_FILTER_TEST_GEQ: return WINDIVERT_FILTER_TEST_LT;
        default:                        return test;
    }
}

/* Compare 128-bit values (word 0 least significant). */
static int cmp128(const UINT32 *a, const UINT32 *b)
{
    int i;
    for (i = 3; i >= 0; i--)
    {
        if (a[i] != b[i])
        {
            return (a[i] < b[i]? -1: 1);
        }
    }
    return 0;
}

static void addr_full(struct pf_addr *a)
{
    memset(a, 0, sizeof(*a));
    memset(a->hi, 0xFF, sizeof(a->hi));
}

static int addr_is_full(const struct pf_addr *a)
{
    static const UINT32 zero[4] = {0}, ones[4] = {~0u, ~0u, ~0u, ~0u};
    return !a->has_excl && cmp128(a->lo, zero) == 0 &&
        cmp128(a->hi, ones) == 0;
}

static void inc128(UINT32 *a)
{
    int i;
    for (i = 0; i < 4 && ++a[i] == 0; i++)
        ;
}

static void dec128(UINT32 *a)
{
    int i;
    for (i = 0; i < 4 && a[i]-- == 0; i++)
        ;
}

static int addr_apply(struct pf_addr *a, UINT test, const UINT32 *arg,
    int *exact)
{
    static const UINT32 zero[4] = {0}, ones[4] = {~0u, ~0u, ~0u, ~0u};
    UINT32 v[4];
    memcpy(v, arg, sizeof(v));
    switch (test)
    {
        case WINDIVERT_FILTER_TEST_EQ:
            if (cmp128(v, a->lo) < 0 || cmp128(v, a->hi) > 0)
            {
                return 0;
            }
            if (a->has_excl && cmp128(v, a->excl) == 0)
            {
                return 0;
            }
            memcpy(a->lo, v, sizeof(v));
            memcpy(a->hi, v, sizeof(v));
            a->has_excl = 0;
            return 1;
        case WINDIVERT_FILTER_TEST_NEQ:
            if (cmp128(v, a->lo) < 0 || cmp128(v, a->hi) > 0)
            {
                return 1;
            }
            if (cmp128(v, a->lo) == 0 && cmp128(v, a->hi) == 0)
            {
                return 0;
            }
            if (cmp128(v, a->lo) == 0)
            {
                inc128(a->lo);
                return 1;
            }
            if (cmp128(v, a->hi) == 0)
            {
                dec128(a->hi);
                return 1;
            }
            if (a->has_excl)
            {
                *exact = 0;
                return 1;
            }
            memcpy(a->excl, v, sizeof(v));
            a->has_excl = 1;
            return 1;
        case WINDIVERT_FILTER_TEST_LT:
            if (cmp128(v, zero) == 0)
            {
                return 0;
            }
            dec128(v);
            /* fallthrough */
        case WINDIVERT_FILTER_TEST_LEQ:
            if (cmp128(v, a->hi) < 0)
            {
                memcpy(a->hi, v, sizeof(v));
            }
            break;
        case WINDIVERT_FILTER_TEST_GT:
            if (cmp128(v, ones) == 0)
            {
                return 0;
            }
            inc128(v);
            /* fallthrough */
        case WINDIVERT_FILTER_TEST_GEQ:
            if (cmp128(v, a->lo) > 0)
            {
                memcpy(a->lo, v, sizeof(v));
            }
            break;
        default:
            *exact = 0;
            return 1;
    }
    if (cmp128(a->lo, a->hi) > 0)
    {
        return 0;
    }
    if (a->has_excl && (cmp128(a->excl, a->lo) < 0 ||
                        cmp128(a->excl, a->hi) > 0))
    {
        a->has_excl = 0;
    }
    return 1;
}

static void cube_init(struct pf_cube *c)
{
    memset(c, 0, sizeof(*c));
    c->exact = 1;
    c->loopback = -1;
    range_full(&c->proto, 255);
    range_full(&c->sport, 65535);
    range_full(&c->dport, 65535);
    range_full(&c->ttl, 255);
    range_full(&c->event, 15);
    range_full(&c->pid, 0xFFFFFFFF);
    addr_full(&c->src);
    addr_full(&c->dst);
}

static int cube_set_ver(struct pf_cube *c, int ver)
{
    if (c->ver != 0 && c->ver != ver)
    {
        return 0;
    }
    c->ver = ver;
    return 1;
}

static int cube_set_proto(struct pf_cube *c, UINT32 proto)
{
    int exact = 1;
    return range_apply(&c->proto, WINDIVERT_FILTER_TEST_EQ, proto, 255,
        &exact);
}

static int cube_proto_is(const struct pf_cube *c, UINT32 proto)
{
    return c->proto.lo == proto && c->proto.hi == proto;
}

/* Does the cube already guarantee that the header behind `field` exists? */
static int cube_has_header(const struct pf_cube *c, UINT field)
{
    switch (field)
    {
        case WINDIVERT_FILTER_FIELD_IP_TTL:
        case WINDIVERT_FILTER_FIELD_IP_PROTOCOL:
        case WINDIVERT_FILTER_FIELD_IP_SRCADDR:
        case WINDIVERT_FILTER_FIELD_IP_DSTADDR:
            return c->ver == 4;
        case WINDIVERT_FILTER_FIELD_IPV6_HOPLIMIT:
        case WINDIVERT_FILTER_FIELD_IPV6_SRCADDR:
        case WINDIVERT_FILTER_FIELD_IPV6_DSTADDR:
            return c->ver == 6;
        case WINDIVERT_FILTER_FIELD_TCP_SRCPORT:
        case WINDIVERT_FILTER_FIELD_TCP_DSTPORT:
        case WINDIVERT_FILTER_FIELD_TCP_SYN:
        case WINDIVERT_FILTER_FIELD_TCP_ACK:
        case WINDIVERT_FILTER_FIELD_TCP_FIN:
        case WINDIVERT_FILTER_FIELD_TCP_RST:
        case WINDIVERT_FILTER_FIELD_TCP_PSH:
        case WINDIVERT_FILTER_FIELD_TCP_URG:
            return cube_proto_is(c, IPPROTO_TCP);
        case WINDIVERT_FILTER_FIELD_UDP_SRCPORT:
        case WINDIVERT_FILTER_FIELD_UDP_DSTPORT:
            return cube_proto_is(c, IPPROTO_UDP);
        case WINDIVERT_FILTER_FIELD_ICMP_TYPE:
        case WINDIVERT_FILTER_FIELD_ICMP_CODE:
            return c->ver == 4 && cube_proto_is(c, IPPROTO_ICMP);
        case WINDIVERT_FILTER_FIELD_ICMPV6_TYPE:
        case WINDIVERT_FILTER_FIELD_ICMPV6_CODE:
            return c->ver == 6 && cube_proto_is(c, IPPROTO_ICMPV6);
        default:
            return 0;
    }
}

/*
 * Impose the header-presence implied by a successful test on `field`.
 * Returns 0 if the cube becomes empty.
 */
static int cube_require_header(struct pf_cube *c, UINT field)
{
    switch (field)
    {
        case WINDIVERT_FILTER_FIELD_IP_HDRLENGTH:
        case WINDIVERT_FILTER_FIELD_IP_TOS:
        case WINDIVERT_FILTER_FIELD_IP_LENGTH:
        case WINDIVERT_FILTER_FIELD_IP_ID:
        case WINDIVERT_FILTER_FIELD_IP_DF:
        case WINDIVERT_FILTER_FIELD_IP_MF:
        case WINDIVERT_FILTER_FIELD_IP_FRAGOFF:
        case WINDIVERT_FILTER_FIELD_IP_TTL:
        case WINDIVERT_FILTER_FIELD_IP_PROTOCOL:
        case WINDIVERT_FILTER_FIELD_IP_CHECKSUM:
        case WINDIVERT_FILTER_FIELD_IP_SRCADDR:
        case WINDIVERT_FILTER_FIELD_IP_DSTADDR:
            return cube_set_ver(c, 4);
        case WINDIVERT_FILTER_FIELD_IPV6_TRAFFICCLASS:
        case WINDIVERT_FILTER_FIELD_IPV6_FLOWLABEL:
        case WINDIVERT_FILTER_FIELD_IPV6_LENGTH:
        case WINDIVERT_FILTER_FIELD_IPV6_NEXTHDR:
        case WINDIVERT_FILTER_FIELD_IPV6_HOPLIMIT:
        case WINDIVERT_FILTER_FIELD_IPV6_SRCADDR:
        case WINDIVERT_FILTER_FIELD_IPV6_DSTADDR:
            return cube_set_ver(c, 6);
        case WINDIVERT_FILTER_FIELD_ICMP_TYPE:
        case WINDIVERT_FILTER_FIELD_ICMP_CODE:
        case WINDIVERT_FILTER_FIELD_ICMP_CHECKSUM:
        case WINDIVERT_FILTER_FIELD_ICMP_BODY:
            return cube_set_ver(c, 4) && cube_set_proto(c, IPPROTO_ICMP);
        case WINDIVERT_FILTER_FIELD_ICMPV6_TYPE:
        case WINDIVERT_FILTER_FIELD_ICMPV6_CODE:
        case WINDIVERT_FILTER_FIELD_ICMPV6_CHECKSUM:
        case WINDIVERT_FILTER_FIELD_ICMPV6_BODY:
            return cube_set_ver(c, 6) && cube_set_proto(c, IPPROTO_ICMPV6);
        case WINDIVERT_FILTER_FIELD_TCP_SRCPORT:
        case WINDIVERT_FILTER_FIELD_TCP_DSTPORT:
        case WINDIVERT_FILTER_FIELD_TCP_SEQNUM:
        case WINDIVERT_FILTER_FIELD_TCP_ACKNUM:
        case WINDIVERT_FILTER_FIELD_TCP_HDRLENGTH:
        case WINDIVERT_FILTER_FIELD_TCP_URG:
        case WINDIVERT_FILTER_FIELD_TCP_ACK:
        case WINDIVERT_FILTER_FIELD_TCP_PSH:
        case WINDIVERT_FILTER_FIELD_TCP_RST:
        case WINDIVERT_FILTER_FIELD_TCP_SYN:
        case WINDIVERT_FILTER_FIELD_TCP_FIN:
        case WINDIVERT_FILTER_FIELD_TCP_WINDOW:
        case WINDIVERT_FILTER_FIELD_TCP_CHECKSUM:
        case WINDIVERT_FILTER_FIELD_TCP_URGPTR:
        case WINDIVERT_FILTER_FIELD_TCP_PAYLOAD:
        case WINDIVERT_FILTER_FIELD_TCP_PAYLOAD16:
        case WINDIVERT_FILTER_FIELD_TCP_PAYLOAD32:
        case WINDIVERT_FILTER_FIELD_TCP_PAYLOADLENGTH:
            return cube_set_proto(c, IPPROTO_TCP);
        case WINDIVERT_FILTER_FIELD_UDP_SRCPORT:
        case WINDIVERT_FILTER_FIELD_UDP_DSTPORT:
        case WINDIVERT_FILTER_FIELD_UDP_LENGTH:
        case WINDIVERT_FILTER_FIELD_UDP_CHECKSUM:
        case WINDIVERT_FILTER_FIELD_UDP_PAYLOAD:
        case WINDIVERT_FILTER_FIELD_UDP_PAYLOAD16:
        case WINDIVERT_FILTER_FIELD_UDP_PAYLOAD32:
        case WINDIVERT_FILTER_FIELD_UDP_PAYLOADLENGTH:
            return cube_set_proto(c, IPPROTO_UDP);
        default:
            return 1;
    }
}

static int is_mapped_ipv4(const UINT32 *arg)
{
    return arg[3] == 0 && arg[2] == 0 && arg[1] == 0x0000FFFF;
}

static int apply_bool(int *slot, UINT test, UINT32 arg, int neg)
{
    /* val is 0 or 1; returns 0 if infeasible, else constrains *slot. */
    int can0, can1, want;
    int cmp0 = (neg? 1: (0 < arg? -1: (0 == arg? 0: 1)));
    int cmp1 = (neg? 1: (1 < arg? -1: (1 == arg? 0: 1)));
#define PF_TEST(cmp)                                        \
    (test == WINDIVERT_FILTER_TEST_EQ?  (cmp) == 0:         \
     test == WINDIVERT_FILTER_TEST_NEQ? (cmp) != 0:         \
     test == WINDIVERT_FILTER_TEST_LT?  (cmp) < 0:          \
     test == WINDIVERT_FILTER_TEST_LEQ? (cmp) <= 0:         \
     test == WINDIVERT_FILTER_TEST_GT?  (cmp) > 0:          \
                                        (cmp) >= 0)
    can0 = PF_TEST(cmp0);
    can1 = PF_TEST(cmp1);
#undef PF_TEST
    if (!can0 && !can1)
    {
        return 0;
    }
    if (can0 && can1)
    {
        return 1;
    }
    want = can1;
    if (*slot >= 0 && *slot != want)
    {
        return 0;
    }
    *slot = want;
    return 1;
}

/* Truth value of `0 <test> arg` (the ZERO field, and EVENT on the network
 * layers where the event is always 0). */
static int zero_test(UINT test, UINT32 arg, int neg)
{
    int cmp = (arg == 0? 0: (neg? 1: -1));
    switch (test)
    {
        case WINDIVERT_FILTER_TEST_EQ:  return cmp == 0;
        case WINDIVERT_FILTER_TEST_NEQ: return cmp != 0;
        case WINDIVERT_FILTER_TEST_LT:  return cmp < 0;
        case WINDIVERT_FILTER_TEST_LEQ: return cmp <= 0;
        case WINDIVERT_FILTER_TEST_GT:  return cmp > 0;
        default:                        return cmp >= 0;
    }
}

static void pf_emit(struct pf_ctx *ctx, const struct pf_cube *c);
static void pf_branch(struct pf_ctx *ctx, const WINDIVERT_FILTER *insn,
    int positive, const struct pf_cube *in);
static void pf_branch_event(struct pf_ctx *ctx, const WINDIVERT_FILTER *insn,
    int positive, const struct pf_cube *in);

/*
 * Apply "field <test> arg" (or its negation when `positive` is 0) to a copy
 * of the cube and continue the walk at `next`.
 */
static void pf_walk(struct pf_ctx *ctx, UINT16 ip, struct pf_cube *c);

static void pf_continue(struct pf_ctx *ctx, UINT16 next, struct pf_cube *c)
{
    if (next == WINDIVERT_FILTER_RESULT_ACCEPT)
    {
        pf_emit(ctx, c);
    }
    else if (next != WINDIVERT_FILTER_RESULT_REJECT)
    {
        pf_walk(ctx, next, c);
    }
}

/*
 * Continue the walk with the cube(s) meaning "the header behind `field` is
 * absent".  Returns 0 if the field has no representable header condition.
 */
static int pf_absent(struct pf_ctx *ctx, UINT16 next, const struct pf_cube *in,
    UINT field)
{
    struct pf_cube c = *in, d = *in;
    UINT32 proto = 0;
    int ver = 0, alt_ver = 0;

    switch (field)
    {
        case WINDIVERT_FILTER_FIELD_IP_TTL:
        case WINDIVERT_FILTER_FIELD_IP_PROTOCOL:
        case WINDIVERT_FILTER_FIELD_IP_SRCADDR:
        case WINDIVERT_FILTER_FIELD_IP_DSTADDR:
            if (cube_set_ver(&c, 6))
            {
                pf_continue(ctx, next, &c);
            }
            return 1;
        case WINDIVERT_FILTER_FIELD_IPV6_HOPLIMIT:
        case WINDIVERT_FILTER_FIELD_IPV6_SRCADDR:
        case WINDIVERT_FILTER_FIELD_IPV6_DSTADDR:
            if (cube_set_ver(&c, 4))
            {
                pf_continue(ctx, next, &c);
            }
            return 1;
        case WINDIVERT_FILTER_FIELD_TCP_SRCPORT:
        case WINDIVERT_FILTER_FIELD_TCP_DSTPORT:
        case WINDIVERT_FILTER_FIELD_TCP_SYN:
        case WINDIVERT_FILTER_FIELD_TCP_ACK:
        case WINDIVERT_FILTER_FIELD_TCP_FIN:
        case WINDIVERT_FILTER_FIELD_TCP_RST:
        case WINDIVERT_FILTER_FIELD_TCP_PSH:
        case WINDIVERT_FILTER_FIELD_TCP_URG:
            proto = IPPROTO_TCP;
            break;
        case WINDIVERT_FILTER_FIELD_UDP_SRCPORT:
        case WINDIVERT_FILTER_FIELD_UDP_DSTPORT:
            proto = IPPROTO_UDP;
            break;
        case WINDIVERT_FILTER_FIELD_ICMP_TYPE:
        case WINDIVERT_FILTER_FIELD_ICMP_CODE:
            proto = IPPROTO_ICMP;
            ver = 4;
            alt_ver = 6;
            break;
        case WINDIVERT_FILTER_FIELD_ICMPV6_TYPE:
        case WINDIVERT_FILTER_FIELD_ICMPV6_CODE:
            proto = IPPROTO_ICMPV6;
            ver = 6;
            alt_ver = 4;
            break;
        default:
            return 0;
    }
    if (alt_ver != 0 && cube_set_ver(&d, alt_ver))
    {
        pf_continue(ctx, next, &d);
    }
    if ((ver == 0 || cube_set_ver(&c, ver)) &&
        range_apply(&c.proto, WINDIVERT_FILTER_TEST_NEQ, proto, 255,
            &c.exact))
    {
        pf_continue(ctx, next, &c);
    }
    return 1;
}

/*
 * Event layers: every field always has a value (no header can be absent),
 * so a failed test is just the negated test.
 */
static void pf_branch_event(struct pf_ctx *ctx, const WINDIVERT_FILTER *insn,
    int positive, const struct pf_cube *in)
{
    struct pf_cube c = *in;
    UINT field = insn->field;
    UINT test = positive? insn->test: negate_test(insn->test);
    UINT16 next = (UINT16)(positive? insn->success: insn->failure);
    const UINT32 *arg = insn->arg;
    int neg = insn->neg;
    int ok = 1;

    switch (field)
    {
        case WINDIVERT_FILTER_FIELD_EVENT:
            ok = !neg && range_apply(&c.event, test, arg[0], 15, &c.exact);
            break;
        case WINDIVERT_FILTER_FIELD_PROCESSID:
            ok = !neg && range_apply(&c.pid, test, arg[0], 0xFFFFFFFF, &c.exact);
            break;
        case WINDIVERT_FILTER_FIELD_PROTOCOL:
            ok = !neg && range_apply(&c.proto, test, arg[0], 255, &c.exact);
            break;
        case WINDIVERT_FILTER_FIELD_LOCALPORT:
            ok = !neg && range_apply(&c.sport, test, arg[0], 65535, &c.exact);
            break;
        case WINDIVERT_FILTER_FIELD_REMOTEPORT:
            ok = !neg && range_apply(&c.dport, test, arg[0], 65535, &c.exact);
            break;
        case WINDIVERT_FILTER_FIELD_LOCALADDR:
            ok = !neg && addr_apply(&c.src, test, arg, &c.exact);
            break;
        case WINDIVERT_FILTER_FIELD_REMOTEADDR:
            ok = !neg && addr_apply(&c.dst, test, arg, &c.exact);
            break;
        case WINDIVERT_FILTER_FIELD_IP:
        case WINDIVERT_FILTER_FIELD_IPV6:
            /* WinDivert evaluates these from IP headers, which events do not
             * have: on FLOW/SOCKET they are always 0. */
            ok = zero_test(test, arg[0], neg);
            break;
        case WINDIVERT_FILTER_FIELD_TCP:
        case WINDIVERT_FILTER_FIELD_UDP:
        {
            UINT32 proto = (field == WINDIVERT_FILTER_FIELD_TCP? IPPROTO_TCP: IPPROTO_UDP);
            int slot = -1;
            ok = apply_bool(&slot, test, arg[0], neg);
            if (ok && slot >= 0)
            {
                ok = range_apply(&c.proto, slot? WINDIVERT_FILTER_TEST_EQ:
                    WINDIVERT_FILTER_TEST_NEQ, proto, 255, &c.exact);
            }
            break;
        }
        default:
            /* loopback, endpoint IDs, icmp, timestamps...: not in the rules. */
            c.exact = 0;
            break;
    }
    if (ok)
    {
        pf_continue(ctx, next, &c);
    }
}

static void pf_branch(struct pf_ctx *ctx, const WINDIVERT_FILTER *insn,
    int positive, const struct pf_cube *in)
{
    struct pf_cube c = *in, alt;
    UINT field = insn->field;
    UINT test = insn->test;
    UINT16 next = (UINT16)(positive? insn->success: insn->failure);
    const UINT32 *arg = insn->arg;
    int neg = insn->neg;
    int ok = 1;

    if (field == WINDIVERT_FILTER_FIELD_ZERO)
    {
        if (zero_test(test, arg[0], neg) == positive)
        {
            pf_continue(ctx, next, &c);
        }
        return;
    }

    if (ctx->event_mode)
    {
        pf_branch_event(ctx, insn, positive, &c);
        return;
    }

    if (!positive)
    {
        /*
         * A failed test means "header absent OR value fails the test".  That
         * is only a plain negated test when the header is known to exist
         * (presence fields always evaluate, so they are always exact).
         */
        int presence = (field == WINDIVERT_FILTER_FIELD_INBOUND ||
            field == WINDIVERT_FILTER_FIELD_OUTBOUND ||
            field == WINDIVERT_FILTER_FIELD_LOOPBACK ||
            field == WINDIVERT_FILTER_FIELD_IP ||
            field == WINDIVERT_FILTER_FIELD_IPV6 ||
            field == WINDIVERT_FILTER_FIELD_TCP ||
            field == WINDIVERT_FILTER_FIELD_UDP ||
            field == WINDIVERT_FILTER_FIELD_ICMP ||
            field == WINDIVERT_FILTER_FIELD_ICMPV6 ||
            field == WINDIVERT_FILTER_FIELD_EVENT);
        if (!presence && !cube_has_header(&c, field))
        {
            /* Branch 1: the header is absent. */
            if (!pf_absent(ctx, next, &c, field))
            {
                c.exact = 0;
                pf_continue(ctx, next, &c);
                return;
            }
            /* Branch 2: the header exists and the test failed. */
            if (!cube_require_header(&c, field))
            {
                return;
            }
        }
        test = negate_test(test);
    }
    else
    {
        ok = cube_require_header(&c, field);
        if (!ok)
        {
            return;
        }
    }

    switch (field)
    {
        case WINDIVERT_FILTER_FIELD_EVENT:
            /* The network layers only have WINDIVERT_EVENT_NETWORK_PACKET. */
            ok = (zero_test(test, arg[0], neg) != 0);
            break;
        case WINDIVERT_FILTER_FIELD_INBOUND:
        case WINDIVERT_FILTER_FIELD_OUTBOUND:
        {
            int out = (c.dir == 0? -1: c.dir == 2);
            int want_in = (field == WINDIVERT_FILTER_FIELD_INBOUND);
            int slot = (out < 0? -1: (want_in? !out: out));
            ok = apply_bool(&slot, test, arg[0], neg);
            if (ok && slot >= 0)
            {
                c.dir = (want_in? (slot? 1: 2): (slot? 2: 1));
            }
            break;
        }
        case WINDIVERT_FILTER_FIELD_LOOPBACK:
            ok = apply_bool(&c.loopback, test, arg[0], neg);
            break;
        case WINDIVERT_FILTER_FIELD_IP:
        case WINDIVERT_FILTER_FIELD_IPV6:
        {
            int is4 = (field == WINDIVERT_FILTER_FIELD_IP);
            int slot = (c.ver == 0? -1: (c.ver == (is4? 4: 6)));
            ok = apply_bool(&slot, test, arg[0], neg);
            if (ok && slot >= 0)
            {
                ok = cube_set_ver(&c, (slot == is4? 4: 6));
            }
            break;
        }
        case WINDIVERT_FILTER_FIELD_TCP:
        case WINDIVERT_FILTER_FIELD_UDP:
        case WINDIVERT_FILTER_FIELD_ICMP:
        case WINDIVERT_FILTER_FIELD_ICMPV6:
        {
            UINT32 proto = (field == WINDIVERT_FILTER_FIELD_TCP? IPPROTO_TCP:
                field == WINDIVERT_FILTER_FIELD_UDP? IPPROTO_UDP:
                field == WINDIVERT_FILTER_FIELD_ICMP? IPPROTO_ICMP:
                IPPROTO_ICMPV6);
            int slot = -1;
            ok = apply_bool(&slot, test, arg[0], neg);
            if (!ok || slot < 0)
            {
                break;
            }
            if (slot)
            {
                ok = cube_set_proto(&c, proto);
                if (ok && field == WINDIVERT_FILTER_FIELD_ICMP)
                {
                    ok = cube_set_ver(&c, 4);
                }
                else if (ok && field == WINDIVERT_FILTER_FIELD_ICMPV6)
                {
                    ok = cube_set_ver(&c, 6);
                }
            }
            else if (field == WINDIVERT_FILTER_FIELD_ICMP ||
                     field == WINDIVERT_FILTER_FIELD_ICMPV6)
            {
                /* not icmp == (ipv6 or proto != 1): split. */
                int v = (field == WINDIVERT_FILTER_FIELD_ICMP? 4: 6);
                alt = c;
                if (cube_set_ver(&alt, (v == 4? 6: 4)))
                {
                    pf_continue(ctx, next, &alt);
                }
                ok = cube_set_ver(&c, v) &&
                    range_apply(&c.proto, WINDIVERT_FILTER_TEST_NEQ, proto,
                        255, &c.exact);
            }
            else
            {
                ok = range_apply(&c.proto, WINDIVERT_FILTER_TEST_NEQ, proto,
                    255, &c.exact);
            }
            break;
        }
        case WINDIVERT_FILTER_FIELD_IP_PROTOCOL:
            ok = !neg && range_apply(&c.proto, test, arg[0], 255, &c.exact);
            break;
        case WINDIVERT_FILTER_FIELD_IP_TTL:
        case WINDIVERT_FILTER_FIELD_IPV6_HOPLIMIT:
            if (test == WINDIVERT_FILTER_TEST_EQ ||
                test == WINDIVERT_FILTER_TEST_NEQ)
            {
                ok = !neg && range_apply(&c.ttl, test, arg[0], 255, &c.exact);
            }
            else
            {
                c.exact = 0;
            }
            break;
        case WINDIVERT_FILTER_FIELD_TCP_SRCPORT:
        case WINDIVERT_FILTER_FIELD_UDP_SRCPORT:
        case WINDIVERT_FILTER_FIELD_ICMP_TYPE:
        case WINDIVERT_FILTER_FIELD_ICMPV6_TYPE:
            ok = !neg && range_apply(&c.sport, test, arg[0], 65535, &c.exact);
            break;
        case WINDIVERT_FILTER_FIELD_TCP_DSTPORT:
        case WINDIVERT_FILTER_FIELD_UDP_DSTPORT:
        case WINDIVERT_FILTER_FIELD_ICMP_CODE:
        case WINDIVERT_FILTER_FIELD_ICMPV6_CODE:
            ok = !neg && range_apply(&c.dport, test, arg[0], 65535, &c.exact);
            break;
        case WINDIVERT_FILTER_FIELD_TCP_URG:
        case WINDIVERT_FILTER_FIELD_TCP_ACK:
        case WINDIVERT_FILTER_FIELD_TCP_PSH:
        case WINDIVERT_FILTER_FIELD_TCP_RST:
        case WINDIVERT_FILTER_FIELD_TCP_SYN:
        case WINDIVERT_FILTER_FIELD_TCP_FIN:
        {
            UINT8 bit = (field == WINDIVERT_FILTER_FIELD_TCP_FIN? 0x01:
                field == WINDIVERT_FILTER_FIELD_TCP_SYN? 0x02:
                field == WINDIVERT_FILTER_FIELD_TCP_RST? 0x04:
                field == WINDIVERT_FILTER_FIELD_TCP_PSH? 0x08:
                field == WINDIVERT_FILTER_FIELD_TCP_ACK? 0x10: 0x20);
            int slot = ((c.tcp_mask & bit)? !!(c.tcp_flags & bit): -1);
            ok = apply_bool(&slot, test, arg[0], neg);
            if (ok && slot >= 0)
            {
                c.tcp_mask |= bit;
                c.tcp_flags = (UINT8)((c.tcp_flags & ~bit) | (slot? bit: 0));
            }
            break;
        }
        case WINDIVERT_FILTER_FIELD_IP_SRCADDR:
        case WINDIVERT_FILTER_FIELD_IP_DSTADDR:
        case WINDIVERT_FILTER_FIELD_IPV6_SRCADDR:
        case WINDIVERT_FILTER_FIELD_IPV6_DSTADDR:
        {
            int is_src = (field == WINDIVERT_FILTER_FIELD_IP_SRCADDR ||
                field == WINDIVERT_FILTER_FIELD_IPV6_SRCADDR);
            if (neg)
            {
                ok = 0;
                break;
            }
            if (field == WINDIVERT_FILTER_FIELD_IP_SRCADDR ||
                field == WINDIVERT_FILTER_FIELD_IP_DSTADDR)
            {
                /* The value of an IPv4 address field is ::ffff:a.b.c.d. */
                UINT32 lo[4] = {0, 0x0000FFFF, 0, 0};
                UINT32 hi[4] = {0xFFFFFFFF, 0x0000FFFF, 0, 0};
                struct pf_addr *a = (is_src? &c.src: &c.dst);
                if (cmp128(a->lo, lo) < 0)
                {
                    memcpy(a->lo, lo, sizeof(lo));
                }
                if (cmp128(a->hi, hi) > 0)
                {
                    memcpy(a->hi, hi, sizeof(hi));
                }
            }
            ok = addr_apply(is_src? &c.src: &c.dst, test, arg, &c.exact);
            break;
        }
        case WINDIVERT_FILTER_FIELD_LOCALADDR:
        case WINDIVERT_FILTER_FIELD_REMOTEADDR:
        case WINDIVERT_FILTER_FIELD_LOCALPORT:
        case WINDIVERT_FILTER_FIELD_REMOTEPORT:
        {
            /*
             * local = outbound? src: dst; remote = outbound? dst: src.  Split
             * the cube by direction when it is not already known.
             */
            int local = (field == WINDIVERT_FILTER_FIELD_LOCALADDR ||
                field == WINDIVERT_FILTER_FIELD_LOCALPORT);
            int is_addr = (field == WINDIVERT_FILTER_FIELD_LOCALADDR ||
                field == WINDIVERT_FILTER_FIELD_REMOTEADDR);
            int d;
            if (neg)
            {
                ok = 0;
                break;
            }
            if (!is_addr && !cube_proto_is(&c, IPPROTO_TCP) &&
                !cube_proto_is(&c, IPPROTO_UDP))
            {
                /*
                 * Ports only exist for TCP/UDP; ICMP and the rest use ad-hoc
                 * values.  Split: TCP, UDP, and "anything else" (widened).
                 */
                static const UINT32 protos[2] = {IPPROTO_TCP, IPPROTO_UDP};
                int k;
                for (k = 0; k < 2; k++)
                {
                    alt = c;
                    if (cube_set_proto(&alt, protos[k]))
                    {
                        pf_branch(ctx, insn, positive, &alt);
                    }
                }
                alt = c;
                if (range_apply(&alt.proto, WINDIVERT_FILTER_TEST_NEQ,
                        IPPROTO_TCP, 255, &alt.exact) &&
                    range_apply(&alt.proto, WINDIVERT_FILTER_TEST_NEQ,
                        IPPROTO_UDP, 255, &alt.exact))
                {
                    alt.exact = 0;
                    pf_continue(ctx, next, &alt);
                }
                return;
            }
            for (d = 1; d <= 2; d++)
            {
                int use_src;
                if (c.dir != 0 && c.dir != d)
                {
                    continue;
                }
                alt = c;
                alt.dir = d;
                use_src = (local? (d == 2): (d == 1));
                if (is_addr)
                {
                    if (!positive && alt.ver == 0)
                    {
                        alt.exact = 0;
                    }
                    else if (addr_apply(use_src? &alt.src: &alt.dst, test,
                                 arg, &alt.exact))
                    {
                        if (alt.ver == 0)
                        {
                            alt.ver = (is_mapped_ipv4(arg)? 4: 6);
                            if (test != WINDIVERT_FILTER_TEST_EQ)
                            {
                                alt.exact = 0;
                                alt.ver = 0;
                                addr_full(use_src? &alt.src: &alt.dst);
                            }
                        }
                    }
                    else
                    {
                        continue;
                    }
                }
                else if (!range_apply(use_src? &alt.sport: &alt.dport, test,
                             arg[0], 65535, &alt.exact))
                {
                    continue;
                }
                pf_continue(ctx, next, &alt);
            }
            return;
        }
        default:
            /* Not representable in the kernel rules: widen. */
            c.exact = 0;
            break;
    }

    if (ok)
    {
        pf_continue(ctx, next, &c);
    }
}

static void pf_walk(struct pf_ctx *ctx, UINT16 ip, struct pf_cube *c)
{
    const WINDIVERT_FILTER *insn;
    if (ctx->overflow)
    {
        return;
    }
    if (ip >= ctx->len || ++ctx->states > PF_MAX_STATES)
    {
        ctx->overflow = 1;
        return;
    }
    insn = &ctx->obj[ip];
    pf_branch(ctx, insn, 1, c);
    pf_branch(ctx, insn, 0, c);
}

static void pf_emit(struct pf_ctx *ctx, const struct pf_cube *c)
{
    if (ctx->ncubes >= PF_MAX_CUBES)
    {
        ctx->overflow = 1;
        return;
    }
    ctx->cubes[ctx->ncubes++] = *c;
}

/*
 * Encode a port-like range into rule start/end/invert.  Returns 0 if the
 * range cannot be expressed exactly (the caller then widens).
 */
static int encode_range(const struct pf_range *r, UINT32 max, UINT16 *start,
    UINT16 *end, int *active, int *invert)
{
    *active = *invert = 0;
    if (range_is_full(r, max))
    {
        return 1;
    }
    if (r->nexcl == 0)
    {
        *start = (UINT16)r->lo;
        *end = (UINT16)r->hi;
        *active = 1;
        return 1;
    }
    if (r->nexcl == 1 && r->lo == 0 && r->hi == max)
    {
        *start = *end = (UINT16)r->excl[0];
        *active = *invert = 1;
        return 1;
    }
    /* Keep the interval, drop the holes. */
    *start = (UINT16)r->lo;
    *end = (UINT16)r->hi;
    *active = (r->lo != 0 || r->hi != max);
    return 0;
}

/*
 * Smallest prefix (from the top of the 128-bit value) covering [lo, hi].
 * Returns the prefix length; *exact is set when the prefix is exactly the
 * interval.
 */
static int cover_prefix(const UINT32 *lo, const UINT32 *hi, UINT32 *base,
    int *exact)
{
    int bits, i;
    for (bits = 0; bits < 128; bits++)
    {
        int w = 3 - bits / 32, b = 31 - bits % 32;
        if (((lo[w] >> b) & 1) != ((hi[w] >> b) & 1))
        {
            break;
        }
    }
    memcpy(base, lo, 4 * sizeof(UINT32));
    for (i = bits; i < 128; i++)
    {
        int w = 3 - i / 32, b = 31 - i % 32;
        base[w] &= ~(1u << b);
    }
    *exact = 1;
    for (i = bits; i < 128; i++)
    {
        int w = 3 - i / 32, b = 31 - i % 32;
        if (((lo[w] >> b) & 1) != 0 || ((hi[w] >> b) & 1) != 1)
        {
            *exact = 0;
            break;
        }
    }
    return bits;
}

static void mask128(int bits, UINT32 *mask)
{
    int i;
    memset(mask, 0, 4 * sizeof(UINT32));
    for (i = 0; i < bits; i++)
    {
        mask[3 - i / 32] |= 1u << (31 - i % 32);
    }
}

/* Encode an address constraint; returns 0 when widened. */
static int encode_addr(const struct pf_addr *a, UINT32 *ip, UINT32 *mask,
    int *active, int *invert)
{
    int exact_prefix, bits;
    *active = *invert = 0;
    if (addr_is_full(a))
    {
        return 1;
    }
    if (a->has_excl)
    {
        UINT32 lo[4] = {0}, hi[4] = {~0u, ~0u, ~0u, ~0u};
        UINT32 lo4[4] = {0, 0x0000FFFF, 0, 0};
        UINT32 hi4[4] = {0xFFFFFFFF, 0x0000FFFF, 0, 0};
        if ((cmp128(a->lo, lo) == 0 && cmp128(a->hi, hi) == 0) ||
            (cmp128(a->lo, lo4) == 0 && cmp128(a->hi, hi4) == 0))
        {
            memcpy(ip, a->excl, 4 * sizeof(UINT32));
            mask128(128, mask);
            *active = *invert = 1;
            return 1;
        }
    }
    bits = cover_prefix(a->lo, a->hi, ip, &exact_prefix);
    mask128(bits, mask);
    *active = (bits > 0);
    return exact_prefix && !a->has_excl;
}

static void to_net16(const UINT32 *v, UINT8 *out)
{
    int i;
    for (i = 0; i < 4; i++)
    {
        UINT32 w = v[3 - i];
        out[4 * i + 0] = (UINT8)(w >> 24);
        out[4 * i + 1] = (UINT8)(w >> 16);
        out[4 * i + 2] = (UINT8)(w >> 8);
        out[4 * i + 3] = (UINT8)w;
    }
}

struct pf_rule_common
{
    UINT16 match_mask, invert_mask;
    UINT8 proto, direction, loopback, ttl, tcp_flags, tcp_flags_mask;
    UINT16 sp_start, sp_end, dp_start, dp_end;
};

/* Fill the family-independent part of a rule; returns 0 when widened. */
static int encode_common(const struct pf_cube *c, struct pf_rule_common *r)
{
    int exact = 1, active, invert;
    UINT16 s, e;

    memset(r, 0, sizeof(*r));
    r->match_mask = MATCH_ENABLED;

    if (!encode_range(&c->proto, 255, &s, &e, &active, &invert))
    {
        exact = 0;
    }
    if (active)
    {
        if (s != e)
        {
            exact = 0;          /* protocol ranges are not supported */
        }
        else
        {
            r->match_mask |= MATCH_PROTO;
            r->invert_mask |= (invert? MATCH_PROTO: 0);
            r->proto = (UINT8)s;
        }
    }
    if (!encode_range(&c->sport, 65535, &r->sp_start, &r->sp_end, &active,
            &invert))
    {
        exact = 0;
    }
    if (active)
    {
        r->match_mask |= MATCH_SRC_PORT;
        r->invert_mask |= (invert? MATCH_SRC_PORT: 0);
    }
    if (!encode_range(&c->dport, 65535, &r->dp_start, &r->dp_end, &active,
            &invert))
    {
        exact = 0;
    }
    if (active)
    {
        r->match_mask |= MATCH_DST_PORT;
        r->invert_mask |= (invert? MATCH_DST_PORT: 0);
    }
    if (!encode_range(&c->ttl, 255, &s, &e, &active, &invert))
    {
        exact = 0;
    }
    if (active)
    {
        if (s != e)
        {
            exact = 0;
        }
        else
        {
            r->match_mask |= MATCH_TTL;
            r->invert_mask |= (invert? MATCH_TTL: 0);
            r->ttl = (UINT8)s;
        }
    }
    if (c->dir != 0)
    {
        r->match_mask |= MATCH_DIRECTION;
        r->direction = (UINT8)c->dir;
    }
    if (c->loopback >= 0)
    {
        r->match_mask |= MATCH_LOOPBACK;
        r->loopback = (UINT8)c->loopback;
    }
    if (c->tcp_mask != 0)
    {
        r->match_mask |= MATCH_TCP_FLAGS;
        r->tcp_flags = c->tcp_flags;
        r->tcp_flags_mask = c->tcp_mask;
    }
    return exact;
}

static int emit_v4(const struct pf_cube *c, struct filter_rule *rule)
{
    struct pf_rule_common r;
    UINT32 ip[4], mask[4];
    int active, invert, exact = encode_common(c, &r);

    memset(rule, 0, sizeof(*rule));
    if (!encode_addr(&c->src, ip, mask, &active, &invert))
    {
        exact = 0;
    }
    if (active)
    {
        rule->match_mask |= MATCH_SRC_IP;
        r.invert_mask |= (invert? MATCH_SRC_IP: 0);
        rule->src_ip = ip[0];
        rule->src_mask = (mask[1] == 0xFFFFFFFF? mask[0]: 0);
    }
    if (!encode_addr(&c->dst, ip, mask, &active, &invert))
    {
        exact = 0;
    }
    if (active)
    {
        rule->match_mask |= MATCH_DST_IP;
        r.invert_mask |= (invert? MATCH_DST_IP: 0);
        rule->dst_ip = ip[0];
        rule->dst_mask = (mask[1] == 0xFFFFFFFF? mask[0]: 0);
    }
    rule->match_mask |= r.match_mask;
    rule->invert_mask = r.invert_mask;
    rule->proto = r.proto;
    rule->direction = r.direction;
    rule->loopback = r.loopback;
    rule->ttl = r.ttl;
    rule->tcp_flags = r.tcp_flags;
    rule->tcp_flags_mask = r.tcp_flags_mask;
    rule->src_port_start = r.sp_start;
    rule->src_port_end = r.sp_end;
    rule->dst_port_start = r.dp_start;
    rule->dst_port_end = r.dp_end;
    return exact;
}

static int emit_v6(const struct pf_cube *c, struct filter_rule_ipv6 *rule)
{
    struct pf_rule_common r;
    UINT32 ip[4], mask[4];
    int active, invert, exact = encode_common(c, &r);

    memset(rule, 0, sizeof(*rule));
    if (!encode_addr(&c->src, ip, mask, &active, &invert))
    {
        exact = 0;
    }
    if (active)
    {
        rule->match_mask |= MATCH_SRC_IP;
        r.invert_mask |= (invert? MATCH_SRC_IP: 0);
        to_net16(ip, rule->src_ip);
        to_net16(mask, rule->src_mask);
    }
    if (!encode_addr(&c->dst, ip, mask, &active, &invert))
    {
        exact = 0;
    }
    if (active)
    {
        rule->match_mask |= MATCH_DST_IP;
        r.invert_mask |= (invert? MATCH_DST_IP: 0);
        to_net16(ip, rule->dst_ip);
        to_net16(mask, rule->dst_mask);
    }
    rule->match_mask |= r.match_mask;
    rule->invert_mask = r.invert_mask;
    rule->proto = r.proto;
    rule->direction = r.direction;
    rule->loopback = r.loopback;
    rule->ttl = r.ttl;
    rule->tcp_flags = r.tcp_flags;
    rule->tcp_flags_mask = r.tcp_flags_mask;
    rule->src_port_start = r.sp_start;
    rule->src_port_end = r.sp_end;
    rule->dst_port_start = r.dp_start;
    rule->dst_port_end = r.dp_end;
    return exact;
}

int pf_lower(const struct wd_filter *f, struct pf_result *out)
{
    struct pf_ctx *ctx;
    struct pf_cube root;
    UINT i;
    int layer = wd_filter_layer(f);

    memset(out, 0, sizeof(*out));
    out->exact = 1;
    if (layer != WINDIVERT_LAYER_NETWORK &&
        layer != WINDIVERT_LAYER_NETWORK_FORWARD)
    {
        return -EINVAL;
    }

    ctx = calloc(1, sizeof(*ctx));
    if (ctx == NULL)
    {
        return -ENOMEM;
    }
    ctx->obj = wd_filter_object(f, &ctx->len);
    cube_init(&root);
    if (ctx->len > 0)
    {
        pf_walk(ctx, 0, &root);
    }

    if (ctx->overflow)
    {
        goto match_all;
    }
    for (i = 0; i < ctx->ncubes; i++)
    {
        const struct pf_cube *c = &ctx->cubes[i];
        if (!c->exact)
        {
            out->exact = 0;
        }
        if (c->ver != 6)
        {
            if (out->n4 == MAX_RULES)
            {
                goto match_all;
            }
            if (!emit_v4(c, &out->v4[out->n4++]))
            {
                out->exact = 0;
            }
        }
        if (c->ver != 4)
        {
            if (out->n6 == MAX_RULES)
            {
                goto match_all;
            }
            if (!emit_v6(c, &out->v6[out->n6++]))
            {
                out->exact = 0;
            }
        }
    }
    free(ctx);
    return 0;

match_all:
    /* Too complex for the kernel tables: capture everything, filter in
     * user space. */
    free(ctx);
    memset(out, 0, sizeof(*out));
    out->exact = 0;
    out->n4 = out->n6 = 1;
    out->v4[0].match_mask = MATCH_ENABLED;
    out->v6[0].match_mask = MATCH_ENABLED;
    return 0;
}


/* Like encode_range() for 32-bit values. */
static int encode_range32(const struct pf_range *r, UINT32 max, UINT32 *lo, UINT32 *hi,
    int *active, int *invert)
{
    *active = *invert = 0;
    if (range_is_full(r, max))
    {
        return 1;
    }
    if (r->nexcl == 0)
    {
        *lo = r->lo;
        *hi = r->hi;
        *active = 1;
        return 1;
    }
    if (r->nexcl == 1 && r->lo == 0 && r->hi == max)
    {
        *lo = *hi = r->excl[0];
        *active = *invert = 1;
        return 1;
    }
    *lo = r->lo;
    *hi = r->hi;
    *active = 1;
    return 0;
}

/* Build a SOCKET-layer kernel rule; returns 0 when it had to be widened. */
static int emit_event_rule(const struct pf_cube *c, struct event_rule *r)
{
    UINT32 lo, hi, ip[4], mask[4];
    int active, invert, exact = c->exact, i;

    memset(r, 0, sizeof(*r));
    r->match_mask = EVM_ENABLED;

    if (!range_is_full(&c->event, 15))
    {
        r->match_mask |= EVM_EVENT;
        for (i = 0; i <= 15; i++)
        {
            if (range_contains(&c->event, (UINT32)i))
            {
                r->event_mask |= (UINT16)(1u << i);
            }
        }
    }
    if (c->ver != 0)
    {
        r->match_mask |= EVM_FAMILY;
        r->family = (UINT8)c->ver;
    }
    if (!encode_range32(&c->proto, 255, &lo, &hi, &active, &invert))
    {
        exact = 0;
    }
    if (active)
    {
        if (lo != hi)
        {
            exact = 0;
        }
        else
        {
            r->match_mask |= EVM_PROTO;
            r->invert_mask |= (invert? EVM_PROTO: 0);
            r->proto = (UINT8)lo;
        }
    }
    if (!encode_range32(&c->sport, 65535, &lo, &hi, &active, &invert))
    {
        exact = 0;
    }
    if (active)
    {
        r->match_mask |= EVM_LPORT;
        r->invert_mask |= (invert? EVM_LPORT: 0);
        r->lport_lo = (UINT16)lo;
        r->lport_hi = (UINT16)hi;
    }
    if (!encode_range32(&c->dport, 65535, &lo, &hi, &active, &invert))
    {
        exact = 0;
    }
    if (active)
    {
        r->match_mask |= EVM_RPORT;
        r->invert_mask |= (invert? EVM_RPORT: 0);
        r->rport_lo = (UINT16)lo;
        r->rport_hi = (UINT16)hi;
    }
    if (!encode_range32(&c->pid, 0xFFFFFFFF, &lo, &hi, &active, &invert))
    {
        exact = 0;
    }
    if (active)
    {
        r->match_mask |= EVM_PID;
        r->invert_mask |= (invert? EVM_PID: 0);
        r->pid_lo = lo;
        r->pid_hi = hi;
    }
    if (!encode_addr(&c->src, ip, mask, &active, &invert))
    {
        exact = 0;
    }
    if (active)
    {
        r->match_mask |= EVM_LADDR;
        r->invert_mask |= (invert? EVM_LADDR: 0);
        to_net16(ip, r->laddr);
        to_net16(mask, r->lmask);
    }
    if (!encode_addr(&c->dst, ip, mask, &active, &invert))
    {
        exact = 0;
    }
    if (active)
    {
        r->match_mask |= EVM_RADDR;
        r->invert_mask |= (invert? EVM_RADDR: 0);
        to_net16(ip, r->raddr);
        to_net16(mask, r->rmask);
    }
    return exact;
}

int pf_lower_events(const struct wd_filter *f, struct event_rule *rules, unsigned max,
    unsigned *n, int *exact)
{
    struct pf_ctx *ctx;
    struct pf_cube root;
    UINT i;

    *n = 0;
    *exact = 1;
    ctx = calloc(1, sizeof(*ctx));
    if (ctx == NULL)
    {
        return -ENOMEM;
    }
    ctx->event_mode = 1;
    ctx->obj = wd_filter_object(f, &ctx->len);
    cube_init(&root);
    if (ctx->len > 0)
    {
        pf_walk(ctx, 0, &root);
    }
    if (ctx->overflow || ctx->ncubes > max)
    {
        *exact = 0;
        free(ctx);
        return 0;
    }
    for (i = 0; i < ctx->ncubes; i++)
    {
        if (!emit_event_rule(&ctx->cubes[i], &rules[i]))
        {
            *exact = 0;
        }
    }
    *n = ctx->ncubes;
    free(ctx);
    return 0;
}

/*
 * Reference implementation of the BPF rule matcher (for tests): mirrors
 * matches_rule_ipv4/ipv6 in ebpfdivert.bpf.c on already-parsed fields.
 */
static int pf_match_common(UINT16 mm, UINT16 inv, const struct pf_pkt *p,
    UINT8 proto, UINT8 direction, UINT8 loopback, UINT8 ttl, UINT8 tcp_flags,
    UINT8 tcp_mask, UINT16 sps, UINT16 spe, UINT16 dps, UINT16 dpe)
{
    if ((mm & MATCH_SRC_PORT) && ((p->sport >= sps && p->sport <= spe) ==
            !!(inv & MATCH_SRC_PORT))) return 0;
    if ((mm & MATCH_DST_PORT) && ((p->dport >= dps && p->dport <= dpe) ==
            !!(inv & MATCH_DST_PORT))) return 0;
    if ((mm & MATCH_PROTO) && ((p->proto == proto) ==
            !!(inv & MATCH_PROTO))) return 0;
    if ((mm & MATCH_DIRECTION) && ((p->direction == direction) ==
            !!(inv & MATCH_DIRECTION))) return 0;
    if ((mm & MATCH_TTL) && ((p->ttl == ttl) == !!(inv & MATCH_TTL)))
        return 0;
    if ((mm & MATCH_TCP_FLAGS) && (((p->tcp_flags & tcp_mask) == tcp_flags) ==
            !!(inv & MATCH_TCP_FLAGS))) return 0;
    if ((mm & MATCH_LOOPBACK) && p->loopback != loopback) return 0;
    return 1;
}

int pf_match(const struct pf_result *res, const struct pf_pkt *p)
{
    UINT i, j;
    if (p->ver == 4)
    {
        for (i = 0; i < res->n4; i++)
        {
            const struct filter_rule *r = &res->v4[i];
            UINT16 mm = r->match_mask, inv = r->invert_mask;
            if (!(mm & MATCH_ENABLED) || (mm & MATCH_FALSE)) continue;
            if ((mm & MATCH_SRC_IP) && (((p->src[0] & r->src_mask) ==
                    (r->src_ip & r->src_mask)) == !!(inv & MATCH_SRC_IP)))
                continue;
            if ((mm & MATCH_DST_IP) && (((p->dst[0] & r->dst_mask) ==
                    (r->dst_ip & r->dst_mask)) == !!(inv & MATCH_DST_IP)))
                continue;
            if (pf_match_common(mm, inv, p, r->proto, r->direction,
                    r->loopback, r->ttl, r->tcp_flags, r->tcp_flags_mask,
                    r->src_port_start, r->src_port_end, r->dst_port_start,
                    r->dst_port_end))
                return 1;
        }
        return 0;
    }
    for (i = 0; i < res->n6; i++)
    {
        const struct filter_rule_ipv6 *r = &res->v6[i];
        UINT16 mm = r->match_mask, inv = r->invert_mask;
        UINT8 src[16], dst[16];
        int src_eq = 1, dst_eq = 1;
        if (!(mm & MATCH_ENABLED) || (mm & MATCH_FALSE)) continue;
        to_net16(p->src, src);
        to_net16(p->dst, dst);
        for (j = 0; j < 16; j++)
        {
            src_eq &= ((src[j] & r->src_mask[j]) ==
                (r->src_ip[j] & r->src_mask[j]));
            dst_eq &= ((dst[j] & r->dst_mask[j]) ==
                (r->dst_ip[j] & r->dst_mask[j]));
        }
        if ((mm & MATCH_SRC_IP) && (src_eq == !!(inv & MATCH_SRC_IP)))
            continue;
        if ((mm & MATCH_DST_IP) && (dst_eq == !!(inv & MATCH_DST_IP)))
            continue;
        if (pf_match_common(mm, inv, p, r->proto, r->direction, r->loopback,
                r->ttl, r->tcp_flags, r->tcp_flags_mask, r->src_port_start,
                r->src_port_end, r->dst_port_start, r->dst_port_end))
            return 1;
    }
    return 0;
}
