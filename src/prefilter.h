// SPDX-License-Identifier: GPL-2.0-or-later OR LGPL-3.0-or-later
#ifndef EBPFDIVERT_PREFILTER_H
#define EBPFDIVERT_PREFILTER_H

#include <stdint.h>
#include "ebpfdivert_shared.h"

struct wd_filter;

/* Kernel rules lowered from a compiled filter (without SNIFF/DROP bits). */
struct pf_result {
    struct filter_rule v4[MAX_RULES];
    struct filter_rule_ipv6 v6[MAX_RULES];
    unsigned n4, n6;
    int exact;      /* rules match exactly the filter; no user-space eval */
};

__attribute__((visibility("hidden")))
int pf_lower(const struct wd_filter *f, struct pf_result *out);

/*
 * Lower a FLOW/SOCKET filter to event rules (used to block SOCKET events in
 * the kernel).  *exact is cleared when the rules are only a superset.
 */
__attribute__((visibility("hidden")))
int pf_lower_events(const struct wd_filter *f, struct event_rule *rules, unsigned max,
                    unsigned *n, int *exact);

/* Parsed packet fields, as the BPF program sees them (for tests). */
struct pf_pkt {
    int ver;
    uint32_t src[4], dst[4];     /* 128-bit, word 0 least significant;
                                    IPv4 in src[0]/dst[0] */
    uint16_t sport, dport;       /* tcp/udp ports, icmp type/code */
    uint8_t proto, direction, loopback, ttl, tcp_flags;
};

__attribute__((visibility("hidden")))
int pf_match(const struct pf_result *res, const struct pf_pkt *p);

#endif /* EBPFDIVERT_PREFILTER_H */
