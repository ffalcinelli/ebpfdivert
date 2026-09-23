// SPDX-License-Identifier: GPL-2.0-or-later OR LGPL-3.0-or-later
/*
 * test_bpf - run the TC programs of ebpfdivert.bpf.o with BPF_PROG_TEST_RUN.
 *
 *  1. Every WinDivert filter vector (tests/wd_vectors.c) is compiled, lowered
 *     to kernel rules exactly as libebpfdivert does, and the packet is run
 *     through the egress program: the kernel must divert whenever the exact
 *     filter matches, and must agree exactly when the lowering is exact.
 *  2. Targeted cases: actions, loop prevention, impostor marking, loopback
 *     single-sighting, non-IP traffic, fragments, shutdown and redirects.
 *
 * Needs root (CAP_BPF + CAP_NET_ADMIN).  Usage: sudo ./test_bpf [ebpfdivert.bpf.o]
 */
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <linux/bpf.h>

#include "ebpfdivert.h"
#include "prefilter.h"
#include "wd.h"

typedef int BOOL;
#define TRUE    1
#define FALSE   0

#include "wd_vectors.c"

#define TC_ACT_UNSPEC   (-1)
#define TC_ACT_SHOT     2
#define TC_ACT_STOLEN   4
#define TC_ACT_REDIRECT 7

#define TEST_PRIO       100
#define FAKE_LO         0xFFFF      /* test_run uses lo; pretend it is not */

static int failures;
static int prog_in, prog_out, rules4_fd, rules6_fd, cfg_fd, stats_fd;
static struct ring_buffer *rb;

#define FAIL(...)                                   \
    do {                                            \
        fprintf(stderr, "  [FAIL] " __VA_ARGS__);   \
        failures++;                                 \
    } while (0)

/* Last ring buffer record. */
static struct {
    int seen;
    struct divert_pkt_header hdr;
    uint8_t data[4096];
} last;

static int on_record(void *ctx, void *data, size_t size)
{
    (void)ctx;
    if (size < sizeof(last.hdr))
        return 0;
    memcpy(&last.hdr, data, sizeof(last.hdr));
    size -= sizeof(last.hdr);
    memcpy(last.data, (uint8_t *)data + sizeof(last.hdr), size < sizeof(last.data) ? size : sizeof(last.data));
    last.seen = 1;
    return 0;
}

static void set_config(uint32_t lo_ifindex, uint32_t flags)
{
    uint32_t key = 0;
    struct divert_config cfg = {
        .priority = TEST_PRIO,
        .snaplen = DIVERT_MAX_PACKET,
        .loop_prevention_mark = LOOP_PREVENTION_MARK,
        .lo_ifindex = lo_ifindex,
        .flags = flags,
        .heartbeat_ns = 0,
        .heartbeat_timeout_ns = 0,
    };
    if (bpf_map_update_elem(cfg_fd, &key, &cfg, BPF_ANY)) {
        perror("config_map");
        exit(1);
    }
}

static void clear_rules(void)
{
    struct filter_rule r4 = {0};
    struct filter_rule_ipv6 r6 = {0};
    uint32_t i;
    for (i = 0; i < MAX_RULES; i++) {
        bpf_map_update_elem(rules4_fd, &i, &r4, BPF_ANY);
        bpf_map_update_elem(rules6_fd, &i, &r6, BPF_ANY);
    }
}

/* Compile, lower and install a filter; returns 1 if lowered exactly. */
static int install_filter(const char *filter, uint16_t action, struct pf_result *res)
{
    struct wd_filter *f = NULL;
    const char *err_str;
    unsigned err_pos, i;
    if (wd_filter_compile(filter, EBPFDIVERT_LAYER_NETWORK, &f, &err_str, &err_pos) != 0 ||
        pf_lower(f, res) != 0) {
        FAIL("cannot compile/lower '%s'\n", filter);
        wd_filter_free(f);
        return -1;
    }
    wd_filter_free(f);
    clear_rules();
    for (i = 0; i < res->n4; i++) {
        res->v4[i].match_mask |= action;
        bpf_map_update_elem(rules4_fd, &i, &res->v4[i], BPF_ANY);
    }
    for (i = 0; i < res->n6; i++) {
        res->v6[i].match_mask |= action;
        bpf_map_update_elem(rules6_fd, &i, &res->v6[i], BPF_ANY);
    }
    return res->exact;
}

/* Prepend an Ethernet header to an IP packet. */
static size_t make_frame(uint8_t *frame, const uint8_t *pkt, size_t len)
{
    memset(frame, 0, 14);
    frame[0] = 0x02;
    frame[6] = 0x02;
    frame[11] = 1;
    frame[12] = ((pkt[0] >> 4) == 6) ? 0x86 : 0x08;
    frame[13] = ((pkt[0] >> 4) == 6) ? 0xDD : 0x00;
    memcpy(frame + 14, pkt, len);
    return len + 14;
}

struct run_opts {
    uint32_t mark;
    uint32_t priority;
    uint32_t ifindex;
};

/* Run a frame through a program; returns the TC action. */
static int run(int prog_fd, const uint8_t *frame, size_t len, const struct run_opts *ro,
               struct __sk_buff *ctx_out)
{
    struct __sk_buff ctx = {0}, out = {0};
    int err;
    DECLARE_LIBBPF_OPTS(bpf_test_run_opts, topts,
        .data_in = frame,
        .data_size_in = (uint32_t)len,
        .ctx_in = &ctx,
        .ctx_size_in = sizeof(ctx),
        .ctx_out = &out,
        .ctx_size_out = sizeof(out),
        .repeat = 1);
    if (ro) {
        ctx.mark = ro->mark;
        ctx.priority = ro->priority;
        ctx.ifindex = ro->ifindex;
    }
    last.seen = 0;
    err = bpf_prog_test_run_opts(prog_fd, &topts);
    if (err) {
        fprintf(stderr, "test_run failed: %s\n", strerror(-err));
        exit(1);
    }
    ring_buffer__consume(rb);
    if (ctx_out)
        *ctx_out = out;
    return (int)topts.retval;
}

static uint64_t get_stat(uint32_t key)
{
    int ncpu = libbpf_num_possible_cpus(), i;
    uint64_t vals[512] = {0}, total = 0;
    if (ncpu > 512)
        ncpu = 512;
    if (bpf_map_lookup_elem(stats_fd, &key, vals) == 0)
        for (i = 0; i < ncpu; i++)
            total += vals[i];
    return total;
}

static void run_vectors(void)
{
    size_t i, n = sizeof(tests) / sizeof(tests[0]);
    uint8_t frame[4096];
    printf("Running %zu WinDivert vectors through the BPF program...\n", n);
    set_config(FAKE_LO, 0);
    for (i = 0; i < n; i++) {
        const struct test *t = &tests[i];
        struct ebpfdivert_address addr;
        struct pf_result res;
        struct wd_filter *f = NULL;
        const char *err_str;
        unsigned err_pos;
        int exact, lowered_exact, ret, diverted, fragment;
        size_t flen;

        if (t->packet->packet_len + 14 > sizeof(frame))
            continue;
        if (wd_filter_compile(t->filter, EBPFDIVERT_LAYER_NETWORK, &f, &err_str, &err_pos))
            continue;   /* covered by test_filter */
        memset(&addr, 0, sizeof(addr));
        addr.layer = EBPFDIVERT_LAYER_NETWORK;
        addr.outbound = 1;
        addr.ipv6 = (t->packet->packet[0] >> 4) == 6;
        exact = wd_filter_eval(f, t->packet->packet, (unsigned)t->packet->packet_len, &addr);
        wd_filter_free(f);
        if (exact < 0)
            continue;

        lowered_exact = install_filter(t->filter, 0, &res);
        if (lowered_exact < 0)
            continue;
        flen = make_frame(frame, t->packet->packet, t->packet->packet_len);
        ret = run(prog_out, frame, flen, NULL, NULL);
        diverted = (ret == TC_ACT_STOLEN);
        fragment = last.seen && (last.hdr.flags & PKT_F_FRAGMENT);

        if (exact && !diverted)
            FAIL("#%zu '%s' on %s: exact match but kernel returned %d\n", i, t->filter,
                 t->packet->name, ret);
        if (lowered_exact && !fragment && diverted != exact)
            FAIL("#%zu '%s' on %s: exact lowering but kernel %d != filter %d\n", i, t->filter,
                 t->packet->name, diverted, exact);
        if (diverted) {
            if (!last.seen)
                FAIL("#%zu '%s': diverted without a ring record\n", i, t->filter);
            else if (last.hdr.cap_len != flen || last.hdr.l2_len != 14 ||
                     memcmp(last.data, frame, flen) != 0 || last.hdr.direction != 2)
                FAIL("#%zu '%s': ring record mismatch (cap %u, l2 %u, dir %u)\n", i, t->filter,
                     last.hdr.cap_len, last.hdr.l2_len, last.hdr.direction);
        } else if (last.seen) {
            FAIL("#%zu '%s': not diverted but produced a ring record\n", i, t->filter);
        }
    }
}

static const uint8_t *pkt_http(size_t *len)
{
    *len = sizeof(http_request);
    return http_request;
}

static void expect(const char *name, int got, int want)
{
    if (got != want)
        FAIL("%s: got %d, want %d\n", name, got, want);
    else
        printf("  [PASS] %s\n", name);
}

static void run_targeted(void)
{
    uint8_t frame[4096];
    struct pf_result res;
    struct run_opts ro;
    struct __sk_buff out;
    size_t plen, flen;
    const uint8_t *pkt = pkt_http(&plen);
    uint64_t before;

    printf("Running targeted cases...\n");
    flen = make_frame(frame, pkt, plen);
    set_config(FAKE_LO, 0);

    install_filter("tcp.DstPort == 80", MATCH_SNIFF, &res);
    expect("sniff returns UNSPEC", run(prog_out, frame, flen, NULL, NULL), TC_ACT_UNSPEC);
    expect("sniff still records", last.seen && (last.hdr.flags & PKT_F_SNIFFED) != 0, 1);

    install_filter("tcp.DstPort == 80", MATCH_DROP, &res);
    before = get_stat(STAT_DROPPED);
    expect("drop returns SHOT", run(prog_out, frame, flen, NULL, NULL), TC_ACT_SHOT);
    expect("drop counted", (int)(get_stat(STAT_DROPPED) - before), 1);

    install_filter("tcp.DstPort == 80", 0, &res);
    expect("divert returns STOLEN", run(prog_out, frame, flen, NULL, NULL), TC_ACT_STOLEN);
    expect("non-matching port passes", (install_filter("tcp.DstPort == 81", 0, &res),
           run(prog_out, frame, flen, NULL, NULL)), TC_ACT_UNSPEC);

    install_filter("true", 0, &res);
    memset(&ro, 0, sizeof(ro));
    ro.mark = LOOP_PREVENTION_MARK | TEST_PRIO;
    expect("own injection is skipped", run(prog_out, frame, flen, &ro, NULL), TC_ACT_UNSPEC);
    ro.mark = LOOP_PREVENTION_MARK | (TEST_PRIO + 5);
    expect("lower-priority injection is skipped", run(prog_out, frame, flen, &ro, NULL),
           TC_ACT_UNSPEC);
    ro.mark = LOOP_PREVENTION_MARK | (TEST_PRIO - 5);
    expect("higher-priority injection is captured", run(prog_out, frame, flen, &ro, NULL),
           TC_ACT_STOLEN);
    expect("... and flagged impostor", last.seen && (last.hdr.flags & PKT_F_IMPOSTOR) != 0, 1);

    /* Loopback: test_run packets arrive on lo. */
    set_config(1, 0);
    expect("lo ingress is skipped", run(prog_in, frame, flen, NULL, NULL), TC_ACT_UNSPEC);
    expect("lo egress is captured", run(prog_out, frame, flen, NULL, NULL), TC_ACT_STOLEN);
    expect("... and flagged loopback", last.seen && (last.hdr.flags & PKT_F_LOOPBACK) != 0, 1);
    set_config(1, CFG_F_SKIP_LO);
    expect("lo skipped when not selected", run(prog_out, frame, flen, NULL, NULL), TC_ACT_UNSPEC);
    set_config(FAKE_LO, 0);

    /* Non-IP (ARP) never matches, even "true". */
    {
        uint8_t arp[64] = {0};
        memcpy(arp, frame, 12);
        arp[12] = 0x08;
        arp[13] = 0x06;
        expect("ARP passes a 'true' filter", run(prog_in, arp, sizeof(arp), NULL, NULL),
               TC_ACT_UNSPEC);
        expect("... without a record", last.seen, 0);
    }

    /* Inbound fragments need FRAGMENTS; outbound are always visible. */
    {
        size_t fl = make_frame(frame, ipv4_fragment_1, sizeof(ipv4_fragment_1));
        install_filter("true", 0, &res);
        expect("inbound fragment skipped by default", run(prog_in, frame, fl, NULL, NULL),
               TC_ACT_UNSPEC);
        set_config(FAKE_LO, CFG_F_FRAGMENTS);
        expect("inbound fragment with FRAGMENTS", run(prog_in, frame, fl, NULL, NULL),
               TC_ACT_STOLEN);
        expect("... flagged fragment", last.seen && (last.hdr.flags & PKT_F_FRAGMENT) != 0, 1);
        set_config(FAKE_LO, 0);
        expect("outbound fragment captured", run(prog_out, frame, fl, NULL, NULL), TC_ACT_STOLEN);
        install_filter("udp.DstPort == 9999", 0, &res);
        expect("fragments reach user space for any non-empty table",
               run(prog_out, frame, fl, NULL, NULL), TC_ACT_STOLEN);
        install_filter("false", 0, &res);
        expect("... but not for 'false'", run(prog_out, frame, fl, NULL, NULL), TC_ACT_UNSPEC);
        flen = make_frame(frame, pkt, plen);
    }

    /* A stale owner heartbeat makes the program fail open. */
    {
        uint32_t key = 0;
        struct divert_config cfg = {
            .priority = TEST_PRIO, .snaplen = DIVERT_MAX_PACKET,
            .loop_prevention_mark = LOOP_PREVENTION_MARK, .lo_ifindex = FAKE_LO,
            .heartbeat_ns = 1, .heartbeat_timeout_ns = 1000000,
        };
        install_filter("true", 0, &res);
        bpf_map_update_elem(cfg_fd, &key, &cfg, BPF_ANY);
        expect("stale heartbeat passes traffic", run(prog_out, frame, flen, NULL, NULL),
               TC_ACT_UNSPEC);
        set_config(FAKE_LO, 0);
    }

    /* Direction-restricted filters skip the other hook entirely. */
    install_filter("true", 0, &res);
    set_config(FAKE_LO, CFG_F_NO_INBOUND);
    expect("NO_INBOUND skips ingress", run(prog_in, frame, flen, NULL, NULL), TC_ACT_UNSPEC);
    set_config(FAKE_LO, CFG_F_NO_OUTBOUND);
    expect("NO_OUTBOUND skips egress", run(prog_out, frame, flen, NULL, NULL), TC_ACT_UNSPEC);
    set_config(FAKE_LO, CFG_F_SHUTDOWN);
    expect("shutdown passes everything", run(prog_out, frame, flen, NULL, NULL), TC_ACT_UNSPEC);
    set_config(FAKE_LO, CFG_F_FORWARD);
    expect("FORWARD layer ignores ingress", run(prog_in, frame, flen, NULL, NULL), TC_ACT_UNSPEC);
    expect("FORWARD layer ignores local egress", run(prog_out, frame, flen, NULL, NULL),
           TC_ACT_UNSPEC);
    set_config(FAKE_LO, 0);

    /* Redirect through lo: not yet on the target -> bpf_redirect. */
    memset(&ro, 0, sizeof(ro));
    ro.mark = REDIRECT_MARK_MASK | 4242;
    expect("redirect mark on lo is redirected", run(prog_in, frame, flen, &ro, NULL),
           TC_ACT_REDIRECT);
    expect("redirect mark on egress passes", run(prog_out, frame, flen, &ro, NULL),
           TC_ACT_UNSPEC);
    ro.priority = REDIRECT_PRIO_MAGIC | TEST_PRIO;
    expect("... carrying the injector priority in the mark",
           (run(prog_in, frame, flen, &ro, &out), (int)(out.mark == (REDIRECTED_MARK | TEST_PRIO))), 1);
    /* On the target: the injector's priority becomes a loop-prevention mark. */
    memset(&ro, 0, sizeof(ro));
    ro.mark = REDIRECTED_MARK | TEST_PRIO;
    expect("redirected packet skipped by its injector", run(prog_in, frame, flen, &ro, &out),
           TC_ACT_UNSPEC);
    expect("... mark rewritten", (int)(out.mark == (LOOP_PREVENTION_MARK | TEST_PRIO)), 1);
    ro.mark = REDIRECTED_MARK | (TEST_PRIO - 10);
    expect("redirected packet from a higher-priority injector is captured",
           run(prog_in, frame, flen, &ro, NULL), TC_ACT_STOLEN);
}

int main(int argc, char **argv)
{
    const char *path = argc > 1 ? argv[1] : "ebpfdivert.bpf.o";
    struct bpf_object *obj;
    struct bpf_program *pin, *pout;

    obj = bpf_object__open_file(path, NULL);
    if (!obj || libbpf_get_error(obj)) {
        fprintf(stderr, "cannot open %s\n", path);
        return 1;
    }
    if (bpf_object__load(obj)) {
        fprintf(stderr, "cannot load %s (root required)\n", path);
        return 1;
    }
    pin = bpf_object__find_program_by_name(obj, "tc_divert_ingress");
    pout = bpf_object__find_program_by_name(obj, "tc_divert_egress");
    prog_in = bpf_program__fd(pin);
    prog_out = bpf_program__fd(pout);
    rules4_fd = bpf_map__fd(bpf_object__find_map_by_name(obj, "filter_rules"));
    rules6_fd = bpf_map__fd(bpf_object__find_map_by_name(obj, "filter_rules_ipv6"));
    cfg_fd = bpf_map__fd(bpf_object__find_map_by_name(obj, "config_map"));
    stats_fd = bpf_map__fd(bpf_object__find_map_by_name(obj, "stats_map"));
    rb = ring_buffer__new(bpf_map__fd(bpf_object__find_map_by_name(obj, "pcap_ringbuf")),
                          on_record, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "ring buffer setup failed\n");
        return 1;
    }

    run_vectors();
    run_targeted();

    ring_buffer__free(rb);
    bpf_object__close(obj);
    if (failures) {
        printf("%d failure(s)\n", failures);
        return 1;
    }
    printf("All BPF tests passed.\n");
    return 0;
}
