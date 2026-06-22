#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <arpa/inet.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <linux/pkt_cls.h>
#include <linux/ipv6.h>
#include "ebpfdivert_shared.h"

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args) {
    return vfprintf(stderr, format, args);
}

void update_rule(int map_fd, __u32 key, __u16 dst_port, __u16 mask, __u16 invert_mask) {
    struct filter_rule rule = {0};
    rule.dst_port_start = dst_port;
    rule.dst_port_end = dst_port;
    rule.match_mask = mask | MATCH_ENABLED;
    rule.invert_mask = invert_mask;
    if (bpf_map_update_elem(map_fd, &key, &rule, BPF_ANY)) {
        fprintf(stderr, "ERROR: updating filter_rules map failed: %s\n", strerror(errno));
        exit(1);
    }
}

void update_rule_advanced(int map_fd, __u32 key, __u32 src_ip, __u32 src_mask, __u32 dst_ip, __u32 dst_mask,
                          __u16 src_port_start, __u16 src_port_end, __u16 dst_port_start, __u16 dst_port_end,
                          __u16 mask, __u16 invert_mask) {
    struct filter_rule rule = {0};
    rule.src_ip = src_ip;
    rule.src_mask = src_mask;
    rule.dst_ip = dst_ip;
    rule.dst_mask = dst_mask;
    rule.src_port_start = src_port_start;
    rule.src_port_end = src_port_end;
    rule.dst_port_start = dst_port_start;
    rule.dst_port_end = dst_port_end;
    rule.match_mask = mask | MATCH_ENABLED;
    rule.invert_mask = invert_mask;
    if (bpf_map_update_elem(map_fd, &key, &rule, BPF_ANY)) {
        fprintf(stderr, "ERROR: updating filter_rules map failed: %s\n", strerror(errno));
        exit(1);
    }
}

void update_rule_ipv6(int map_fd, __u32 key, const char *dst_ip_str, __u16 dst_port, __u16 mask, __u16 invert_mask) {
    struct filter_rule_ipv6 rule = {0};
    if (dst_ip_str) {
        inet_pton(AF_INET6, dst_ip_str, rule.dst_ip);
        memset(rule.dst_mask, 0xFF, 16);
    }
    rule.dst_port_start = dst_port;
    rule.dst_port_end = dst_port;
    rule.match_mask = mask | MATCH_ENABLED;
    rule.invert_mask = invert_mask;
    if (bpf_map_update_elem(map_fd, &key, &rule, BPF_ANY)) {
        fprintf(stderr, "ERROR: updating filter_rules_ipv6 map failed: %s\n", strerror(errno));
        exit(1);
    }
}

void update_rule_ipv6_advanced(int map_fd, __u32 key, const char *src_ip_str, const char *src_mask_str,
                               const char *dst_ip_str, const char *dst_mask_str,
                               __u16 src_port_start, __u16 src_port_end, __u16 dst_port_start, __u16 dst_port_end,
                               __u16 mask, __u16 invert_mask) {
    struct filter_rule_ipv6 rule = {0};
    if (src_ip_str) {
        inet_pton(AF_INET6, src_ip_str, rule.src_ip);
    }
    if (src_mask_str) {
        inet_pton(AF_INET6, src_mask_str, rule.src_mask);
    }
    if (dst_ip_str) {
        inet_pton(AF_INET6, dst_ip_str, rule.dst_ip);
    }
    if (dst_mask_str) {
        inet_pton(AF_INET6, dst_mask_str, rule.dst_mask);
    }
    rule.src_port_start = src_port_start;
    rule.src_port_end = src_port_end;
    rule.dst_port_start = dst_port_start;
    rule.dst_port_end = dst_port_end;
    rule.match_mask = mask | MATCH_ENABLED;
    rule.invert_mask = invert_mask;
    if (bpf_map_update_elem(map_fd, &key, &rule, BPF_ANY)) {
        fprintf(stderr, "ERROR: updating filter_rules_ipv6 map failed: %s\n", strerror(errno));
        exit(1);
    }
}

void get_stat(int stats_fd, __u32 key, __u64 *total) {
    int num_cpus = libbpf_num_possible_cpus();
    __u64 values[num_cpus];
    memset(values, 0, sizeof(values));
    if (bpf_map_lookup_elem(stats_fd, &key, values)) {
        fprintf(stderr, "ERROR: lookup stats_map failed: %s\n", strerror(errno));
        exit(1);
    }
    *total = 0;
    for (int i = 0; i < num_cpus; i++) {
        *total += values[i];
    }
}

struct last_rb_pkt {
    int received;
    struct divert_packet_buffer pkt;
    size_t size;
};

static struct last_rb_pkt g_last_rb_pkt;

static int handle_ringbuf_sample(void *ctx, void *data, size_t size) {
    if (size > sizeof(struct divert_packet_buffer)) {
        size = sizeof(struct divert_packet_buffer);
    }
    memcpy(&g_last_rb_pkt.pkt, data, size);
    g_last_rb_pkt.size = size;
    g_last_rb_pkt.received = 1;
    return 0;
}

void run_bpf_test_packet(int prog_fd, struct ring_buffer *rb, const char *msg,
                         const void *pkt_data, size_t pkt_len,
                         const struct __sk_buff *ctx_in,
                         int expected_retval,
                         int expect_rb_capture,
                         __u16 expected_direction,
                         __u16 expected_l2_len) {
    g_last_rb_pkt.received = 0;

    struct bpf_test_run_opts opts = {
        .sz = sizeof(struct bpf_test_run_opts),
        .data_in = pkt_data,
        .data_size_in = pkt_len,
        .repeat = 1,
    };
    if (ctx_in) {
        opts.ctx_in = ctx_in;
        opts.ctx_size_in = sizeof(struct __sk_buff);
    }

    int err = bpf_prog_test_run_opts(prog_fd, &opts);
    if (err) {
        printf("  [FAIL] %s: bpf_prog_test_run_opts failed: %s\n", msg, strerror(errno));
        exit(1);
    }

    if (opts.retval != expected_retval) {
        printf("  [FAIL] %s: expected retval=%d, got %d\n", msg, expected_retval, opts.retval);
        exit(1);
    }

    // Read from ring buffer if it exists
    if (rb) {
        ring_buffer__poll(rb, expect_rb_capture ? 50 : 10);
        
        if (expect_rb_capture) {
            if (!g_last_rb_pkt.received) {
                printf("  [FAIL] %s: expected packet in ring buffer, but none received\n", msg);
                exit(1);
            }
            // Validate headers
            if (g_last_rb_pkt.pkt.header.pkt_len != pkt_len) {
                printf("  [FAIL] %s: ringbuf pkt_len mismatch (expected %zu, got %u)\n", msg, pkt_len, g_last_rb_pkt.pkt.header.pkt_len);
                exit(1);
            }
            if (g_last_rb_pkt.pkt.header.direction != expected_direction) {
                printf("  [FAIL] %s: ringbuf direction mismatch (expected %u, got %u)\n", msg, expected_direction, g_last_rb_pkt.pkt.header.direction);
                exit(1);
            }
            if (g_last_rb_pkt.pkt.header.l2_len != expected_l2_len) {
                printf("  [FAIL] %s: ringbuf l2_len mismatch (expected %u, got %u)\n", msg, expected_l2_len, g_last_rb_pkt.pkt.header.l2_len);
                exit(1);
            }
            if (g_last_rb_pkt.pkt.header.pad != 0xDEADC0DE) {
                printf("  [FAIL] %s: ringbuf header pad mismatch (expected 0xDEADC0DE, got 0x%X)\n", msg, g_last_rb_pkt.pkt.header.pad);
                exit(1);
            }
        } else {
            if (g_last_rb_pkt.received) {
                printf("  [FAIL] %s: did not expect packet in ring buffer, but one was received\n", msg);
                exit(1);
            }
        }
    }

    printf("  [PASS] %s (retval=%d%s)\n", msg, opts.retval, expect_rb_capture ? ", captured in ringbuf" : "");
}

void test_packet(int prog_fd, struct ring_buffer *rb, const char *msg, int expected_retval, __u16 dport, int expect_rb_capture) {
    char packet[128];
    memset(packet, 0, sizeof(packet));

    struct iphdr *ip = (struct iphdr *)packet;
    ip->version = 4;
    ip->ihl = 5;
    ip->protocol = 6; // TCP
    ip->saddr = inet_addr("127.0.0.1");
    ip->daddr = inet_addr("127.0.0.1");
    ip->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr));

    struct tcphdr *tcp = (struct tcphdr *)(packet + sizeof(struct iphdr));
    tcp->source = htons(12345);
    tcp->dest = htons(dport);

    run_bpf_test_packet(prog_fd, rb, msg, packet, sizeof(packet), NULL, expected_retval, expect_rb_capture, 2, 0);
}

void test_packet_advanced(int prog_fd, struct ring_buffer *rb, const char *msg, int expected_retval,
                           const char *sip_str, const char *dip_str, __u16 sport, __u16 dport, int expect_rb_capture) {
    char packet[128];
    memset(packet, 0, sizeof(packet));

    struct iphdr *ip = (struct iphdr *)packet;
    ip->version = 4;
    ip->ihl = 5;
    ip->protocol = 6; // TCP
    ip->saddr = inet_addr(sip_str);
    ip->daddr = inet_addr(dip_str);
    ip->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr));

    struct tcphdr *tcp = (struct tcphdr *)(packet + sizeof(struct iphdr));
    tcp->source = htons(sport);
    tcp->dest = htons(dport);

    run_bpf_test_packet(prog_fd, rb, msg, packet, sizeof(packet), NULL, expected_retval, expect_rb_capture, 2, 0);
}

void test_packet_ipv6(int prog_fd, struct ring_buffer *rb, const char *msg, int expected_retval, const char *dip_str, __u16 dport, int expect_rb_capture) {
    char packet[128];
    memset(packet, 0, sizeof(packet));

    struct ipv6hdr *ip6 = (struct ipv6hdr *)packet;
    ip6->version = 6;
    ip6->nexthdr = 6; // TCP
    ip6->hop_limit = 64;
    inet_pton(AF_INET6, "::1", &ip6->saddr);
    inet_pton(AF_INET6, dip_str, &ip6->daddr);

    struct tcphdr *tcp = (struct tcphdr *)(packet + sizeof(struct ipv6hdr));
    tcp->source = htons(12345);
    tcp->dest = htons(dport);

    run_bpf_test_packet(prog_fd, rb, msg, packet, sizeof(packet), NULL, expected_retval, expect_rb_capture, 2, 0);
}

void test_packet_ipv6_advanced(int prog_fd, struct ring_buffer *rb, const char *msg, int expected_retval,
                               const char *sip_str, const char *dip_str, __u16 sport, __u16 dport, int expect_rb_capture) {
    char packet[128];
    memset(packet, 0, sizeof(packet));

    struct ipv6hdr *ip6 = (struct ipv6hdr *)packet;
    ip6->version = 6;
    ip6->nexthdr = 6; // TCP
    ip6->hop_limit = 64;
    inet_pton(AF_INET6, sip_str, &ip6->saddr);
    inet_pton(AF_INET6, dip_str, &ip6->daddr);

    struct tcphdr *tcp = (struct tcphdr *)(packet + sizeof(struct ipv6hdr));
    tcp->source = htons(sport);
    tcp->dest = htons(dport);

    run_bpf_test_packet(prog_fd, rb, msg, packet, sizeof(packet), NULL, expected_retval, expect_rb_capture, 2, 0);
}

void test_packet_ipv6_ext(int prog_fd, struct ring_buffer *rb, const char *msg, int expected_retval, const char *dip_str, __u16 dport, int expect_rb_capture) {
    char packet[128];
    memset(packet, 0, sizeof(packet));

    struct ipv6hdr *ip6 = (struct ipv6hdr *)packet;
    ip6->version = 6;
    ip6->nexthdr = 0; // Hop-by-Hop options
    ip6->hop_limit = 64;
    inet_pton(AF_INET6, "::1", &ip6->saddr);
    inet_pton(AF_INET6, dip_str, &ip6->daddr);

    // Hop-by-Hop extension header (8 bytes)
    __u8 *ext = (__u8 *)(packet + sizeof(struct ipv6hdr));
    ext[0] = 6; // Next Header is TCP
    ext[1] = 0; // Length in 8-octet units minus 1 (0 means 8 bytes total)

    struct tcphdr *tcp = (struct tcphdr *)(packet + sizeof(struct ipv6hdr) + 8);
    tcp->source = htons(12345);
    tcp->dest = htons(dport);

    run_bpf_test_packet(prog_fd, rb, msg, packet, sizeof(packet), NULL, expected_retval, expect_rb_capture, 2, 0);
}

void test_packet_qinq(int prog_fd, struct ring_buffer *rb, const char *msg, int expected_retval, __u16 dport, int expect_rb_capture) {
    char packet[128];
    memset(packet, 0, sizeof(packet));

    // Outer Ethernet header + outer VLAN tag (18 bytes) + inner VLAN tag (4 bytes) = 22 bytes total L2
    __u16 *p16 = (__u16 *)packet;
    p16[6] = htons(0x88A8);
    p16[7] = htons(10);
    p16[8] = htons(0x8100);
    p16[9] = htons(20);
    p16[10] = htons(0x0800);

    // IPv4 header starts at offset 22
    struct iphdr *ip = (struct iphdr *)(packet + 22);
    ip->version = 4;
    ip->ihl = 5;
    ip->protocol = 6; // TCP
    ip->saddr = inet_addr("127.0.0.1");
    ip->daddr = inet_addr("127.0.0.1");
    ip->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr));

    struct tcphdr *tcp = (struct tcphdr *)(packet + 22 + sizeof(struct iphdr));
    tcp->source = htons(12345);
    tcp->dest = htons(dport);

    run_bpf_test_packet(prog_fd, rb, msg, packet, sizeof(packet), NULL, expected_retval, expect_rb_capture, 2, 22);
}

void test_loop_prevention(int prog_fd, struct ring_buffer *rb, const char *msg) {
    char packet[128];
    memset(packet, 0, sizeof(packet));

    struct iphdr *ip = (struct iphdr *)packet;
    ip->version = 4;
    ip->ihl = 5;
    ip->protocol = 6; // TCP
    ip->saddr = inet_addr("127.0.0.1");
    ip->daddr = inet_addr("127.0.0.1");
    ip->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr));

    struct tcphdr *tcp = (struct tcphdr *)(packet + sizeof(struct iphdr));
    tcp->source = htons(12345);
    tcp->dest = htons(80);

    struct __sk_buff ctx = {0};
    ctx.mark = 0x4D490000 | 10; // injected priority = 10

    run_bpf_test_packet(prog_fd, rb, msg, packet, sizeof(packet), &ctx, -1, 0, 2, 0);
}

void update_rule_icmp(int map_fd, __u32 key, __u8 type, __u8 code, __u16 mask) {
    struct filter_rule rule = {0};
    rule.proto = 1; // ICMP
    rule.icmp_type_start = type;
    rule.icmp_type_end = type;
    rule.icmp_code_start = code;
    rule.icmp_code_end = code;
    rule.match_mask = mask | MATCH_ENABLED | MATCH_PROTO;
    if (bpf_map_update_elem(map_fd, &key, &rule, BPF_ANY)) {
        fprintf(stderr, "ERROR: updating filter_rules map failed: %s\n", strerror(errno));
        exit(1);
    }
}

void update_rule_icmp6(int map_fd, __u32 key, __u8 type, __u8 code, __u16 mask) {
    struct filter_rule_ipv6 rule = {0};
    rule.proto = 58; // ICMPv6
    rule.icmp_type_start = type;
    rule.icmp_type_end = type;
    rule.icmp_code_start = code;
    rule.icmp_code_end = code;
    rule.match_mask = mask | MATCH_ENABLED | MATCH_PROTO;
    if (bpf_map_update_elem(map_fd, &key, &rule, BPF_ANY)) {
        fprintf(stderr, "ERROR: updating filter_rules_ipv6 map failed: %s\n", strerror(errno));
        exit(1);
    }
}

void test_packet_icmp(int prog_fd, struct ring_buffer *rb, const char *msg, int expected_retval, __u8 type, __u8 code, int expect_rb_capture) {
    char packet[128];
    memset(packet, 0, sizeof(packet));

    struct iphdr *ip = (struct iphdr *)packet;
    ip->version = 4;
    ip->ihl = 5;
    ip->protocol = 1; // ICMP
    ip->saddr = inet_addr("127.0.0.1");
    ip->daddr = inet_addr("127.0.0.1");
    ip->tot_len = htons(sizeof(struct iphdr) + 8);

    __u8 *icmp = (__u8 *)(packet + sizeof(struct iphdr));
    icmp[0] = type;
    icmp[1] = code;

    run_bpf_test_packet(prog_fd, rb, msg, packet, sizeof(packet), NULL, expected_retval, expect_rb_capture, 2, 0);
}

void test_packet_icmp6(int prog_fd, struct ring_buffer *rb, const char *msg, int expected_retval, __u8 type, __u8 code, int expect_rb_capture) {
    char packet[128];
    memset(packet, 0, sizeof(packet));

    struct ipv6hdr *ip6 = (struct ipv6hdr *)packet;
    ip6->version = 6;
    ip6->nexthdr = 58; // ICMPv6
    ip6->hop_limit = 64;
    inet_pton(AF_INET6, "::1", &ip6->saddr);
    inet_pton(AF_INET6, "2001:db8::1", &ip6->daddr);

    __u8 *icmp6 = (__u8 *)(packet + sizeof(struct ipv6hdr));
    icmp6[0] = type;
    icmp6[1] = code;

    run_bpf_test_packet(prog_fd, rb, msg, packet, sizeof(packet), NULL, expected_retval, expect_rb_capture, 2, 0);
}

int main(int argc, char **argv) {
    libbpf_set_print(libbpf_print_fn);
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <bpf_object_file>\n", argv[0]);
        return 1;
    }

    struct bpf_object *obj = bpf_object__open_file(argv[1], NULL);
    if (!obj) {
        fprintf(stderr, "ERROR: opening BPF object file failed\n");
        return 1;
    }

    struct bpf_map *rodata = bpf_object__find_map_by_name(obj, ".rodata");
    if (rodata) {
        __u32 new_snaplen = 512;
        if (bpf_map__set_initial_value(rodata, &new_snaplen, sizeof(new_snaplen))) {
            fprintf(stderr, "WARNING: setting initial value for .rodata failed\n");
        } else {
            printf("  [INFO] Successfully set snaplen to %u via .rodata map\n", new_snaplen);
        }
    } else {
        fprintf(stderr, "WARNING: .rodata map not found\n");
    }

    if (bpf_object__load(obj)) {
        fprintf(stderr, "ERROR: loading BPF object file failed\n");
        return 1;
    }

    int map_fd = bpf_object__find_map_fd_by_name(obj, "filter_rules");
    int map_fd_v6 = bpf_object__find_map_fd_by_name(obj, "filter_rules_ipv6");
    int stats_fd = bpf_object__find_map_fd_by_name(obj, "stats_map");
    int ringbuf_fd = bpf_object__find_map_fd_by_name(obj, "pcap_ringbuf");
    struct bpf_program *prog = bpf_object__find_program_by_name(obj, "tc_divert_egress");
    if (map_fd < 0 || map_fd_v6 < 0 || stats_fd < 0 || ringbuf_fd < 0 || !prog) {
        fprintf(stderr, "ERROR: finding maps or program failed\n");
        return 1;
    }
    int prog_fd = bpf_program__fd(prog);

    struct ring_buffer *rb = ring_buffer__new(ringbuf_fd, handle_ringbuf_sample, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "ERROR: failed to initialize ring buffer consumer\n");
        return 1;
    }

    printf("Running eBPF C Tests...\n");

    // Case 1: Match and Divert (with Telemetry verification)
    __u64 stats_before = 0, stats_after = 0;
    get_stat(stats_fd, STAT_DIVERTED, &stats_before);

    update_rule(map_fd, 0, 80, MATCH_DST_PORT, 0);
    test_packet(prog_fd, rb, "Match and Divert", 4, 80, 1);

    get_stat(stats_fd, STAT_DIVERTED, &stats_after);
    if (stats_after == stats_before + 1) {
        printf("  [PASS] Telemetry STAT_DIVERTED incremented correctly.\n");
    } else {
        printf("  [FAIL] Telemetry STAT_DIVERTED validation failed. Before: %llu, After: %llu\n", stats_before, stats_after);
        exit(1);
    }

    // Case 2: Match and Sniff
    update_rule(map_fd, 0, 80, MATCH_DST_PORT | MATCH_SNIFF, 0);
    test_packet(prog_fd, rb, "Match and Sniff", -1, 80, 1);

    // Case 3: Match and Drop
    update_rule(map_fd, 0, 80, MATCH_DST_PORT | MATCH_DROP, 0);
    test_packet(prog_fd, rb, "Match and Drop", 2, 80, 0);

    // Case 4: No Match
    update_rule(map_fd, 0, 80, MATCH_DST_PORT, 0);
    test_packet(prog_fd, rb, "No Match (different port)", -1, 8080, 0);

    // Case 5: Match Inversion (Match all NOT port 80)
    update_rule(map_fd, 0, 80, MATCH_DST_PORT, MATCH_DST_PORT);
    test_packet(prog_fd, rb, "Match Inversion - Divert non-80 (port 8080)", 4, 8080, 1);
    test_packet(prog_fd, rb, "Match Inversion - Skip 80 (port 80)", -1, 80, 0);

    // Case 6: IPv6 Match and Divert
    update_rule_ipv6(map_fd_v6, 0, "2001:db8::1", 80, MATCH_DST_IP | MATCH_DST_PORT, 0);
    test_packet_ipv6(prog_fd, rb, "IPv6 Match and Divert", 4, "2001:db8::1", 80, 1);

    // Case 7: IPv6 Match but different IP (No Match)
    test_packet_ipv6(prog_fd, rb, "IPv6 No Match (different IP)", -1, "2001:db8::2", 80, 0);

    // Case 8: IPv6 Match with Hop-by-Hop Extension Header
    update_rule_ipv6(map_fd_v6, 0, "2001:db8::1", 80, MATCH_DST_IP | MATCH_DST_PORT, 0);
    test_packet_ipv6_ext(prog_fd, rb, "IPv6 Match with Hop-by-Hop Ext Header", 4, "2001:db8::1", 80, 1);

    // Case 9: QinQ packet parsing and diversion
    update_rule(map_fd, 0, 80, MATCH_DST_PORT, 0);
    test_packet_qinq(prog_fd, rb, "QinQ Match and Divert", 4, 80, 1);

    // Case 10: IPv4 Subnet/CIDR match (e.g. 192.168.1.0/24 subnet match)
    update_rule_advanced(map_fd, 0,
                         0, 0, // src
                         ntohl(inet_addr("192.168.1.0")), ntohl(inet_addr("255.255.255.0")), // dst subnet
                         0, 0, 80, 80, // dst port 80
                         MATCH_DST_IP | MATCH_DST_PORT, 0);
    test_packet_advanced(prog_fd, rb, "IPv4 Subnet Match (inside /24)", 4, "10.0.0.1", "192.168.1.42", 12345, 80, 1);

    // Case 11: IPv4 Subnet/CIDR mismatch (outside subnet)
    test_packet_advanced(prog_fd, rb, "IPv4 Subnet Mismatch (outside /24)", -1, "10.0.0.1", "192.168.2.42", 12345, 80, 0);

    // Case 12: IPv6 Subnet/CIDR match (e.g. 2001:db8:abcd::/48 subnet match)
    update_rule_ipv6_advanced(map_fd_v6, 0,
                               NULL, NULL, // src
                               "2001:db8:abcd::", "ffff:ffff:ffff::", // dst subnet
                               0, 0, 80, 80, // dst port 80
                               MATCH_DST_IP | MATCH_DST_PORT, 0);
    test_packet_ipv6_advanced(prog_fd, rb, "IPv6 Subnet Match (inside /48)", 4, "::1", "2001:db8:abcd:12:34::56", 12345, 80, 1);

    // Case 13: IPv6 Subnet/CIDR mismatch (outside subnet)
    test_packet_ipv6_advanced(prog_fd, rb, "IPv6 Subnet Mismatch (outside /48)", -1, "::1", "2001:db8:affe:12:34::56", 12345, 80, 0);

    // Case 14: Port range match (e.g. port 8000-8010)
    update_rule_advanced(map_fd, 0,
                         0, 0, 0, 0, // IPs
                         0, 0, 8000, 8010, // dst port range 8000-8010
                         MATCH_DST_PORT, 0);
    test_packet(prog_fd, rb, "Port Range Match (port 8005)", 4, 8005, 1);
    test_packet(prog_fd, rb, "Port Range Mismatch (port 8015)", -1, 8015, 0);

    // Case 15: Loop Prevention check
    test_loop_prevention(prog_fd, rb, "Loop Prevention behavior (ignored)");

    // Case 16: ICMP type/code match and divert (e.g. Type 8 Code 0 - Echo Request)
    update_rule_icmp(map_fd, 0, 8, 0, MATCH_SRC_PORT | MATCH_DST_PORT);
    test_packet_icmp(prog_fd, rb, "ICMP Match and Divert (Echo Request)", 4, 8, 0, 1);
    test_packet_icmp(prog_fd, rb, "ICMP Mismatch - different type (Echo Reply)", -1, 0, 0, 0);

    // Case 17: ICMPv6 type/code match and divert (e.g. Type 128 Code 0 - Echo Request)
    update_rule_icmp6(map_fd_v6, 0, 128, 0, MATCH_SRC_PORT | MATCH_DST_PORT);
    test_packet_icmp6(prog_fd, rb, "ICMPv6 Match and Divert (Echo Request)", 4, 128, 0, 1);
    test_packet_icmp6(prog_fd, rb, "ICMPv6 Mismatch - different type (Echo Reply)", -1, 129, 0, 0);

    printf("All eBPF C Tests passed!\n");
    ring_buffer__free(rb);
    bpf_object__close(obj);
    return 0;
}
