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

void test_packet(int prog_fd, const char *msg, int expected_retval, __u16 dport) {
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

    struct bpf_test_run_opts opts = {
        .sz = sizeof(struct bpf_test_run_opts),
        .data_in = packet,
        .data_size_in = sizeof(packet),
        .repeat = 1,
    };

    int err = bpf_prog_test_run_opts(prog_fd, &opts);
    if (err) {
        printf("  [FAIL] %s: bpf_prog_test_run_opts failed: %s\n", msg, strerror(errno));
        exit(1);
    }

    if (opts.retval == expected_retval) {
        printf("  [PASS] %s (retval=%d)\n", msg, opts.retval);
    } else {
        printf("  [FAIL] %s: expected retval=%d, got %d\n", msg, expected_retval, opts.retval);
        exit(1);
    }
}

void test_packet_advanced(int prog_fd, const char *msg, int expected_retval, const char *sip_str, const char *dip_str, __u16 sport, __u16 dport) {
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

    struct bpf_test_run_opts opts = {
        .sz = sizeof(struct bpf_test_run_opts),
        .data_in = packet,
        .data_size_in = sizeof(packet),
        .repeat = 1,
    };

    int err = bpf_prog_test_run_opts(prog_fd, &opts);
    if (err) {
        printf("  [FAIL] %s: bpf_prog_test_run_opts failed: %s\n", msg, strerror(errno));
        exit(1);
    }

    if (opts.retval == expected_retval) {
        printf("  [PASS] %s (retval=%d)\n", msg, opts.retval);
    } else {
        printf("  [FAIL] %s: expected retval=%d, got %d\n", msg, expected_retval, opts.retval);
        exit(1);
    }
}

void test_packet_ipv6(int prog_fd, const char *msg, int expected_retval, const char *dip_str, __u16 dport) {
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

    struct bpf_test_run_opts opts = {
        .sz = sizeof(struct bpf_test_run_opts),
        .data_in = packet,
        .data_size_in = sizeof(packet),
        .repeat = 1,
    };

    int err = bpf_prog_test_run_opts(prog_fd, &opts);
    if (err) {
        printf("  [FAIL] %s: bpf_prog_test_run_opts failed: %s\n", msg, strerror(errno));
        exit(1);
    }

    if (opts.retval == expected_retval) {
        printf("  [PASS] %s (retval=%d)\n", msg, opts.retval);
    } else {
        printf("  [FAIL] %s: expected retval=%d, got %d\n", msg, expected_retval, opts.retval);
        exit(1);
    }
}

void test_packet_ipv6_advanced(int prog_fd, const char *msg, int expected_retval, const char *sip_str, const char *dip_str, __u16 sport, __u16 dport) {
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

    struct bpf_test_run_opts opts = {
        .sz = sizeof(struct bpf_test_run_opts),
        .data_in = packet,
        .data_size_in = sizeof(packet),
        .repeat = 1,
    };

    int err = bpf_prog_test_run_opts(prog_fd, &opts);
    if (err) {
        printf("  [FAIL] %s: bpf_prog_test_run_opts failed: %s\n", msg, strerror(errno));
        exit(1);
    }

    if (opts.retval == expected_retval) {
        printf("  [PASS] %s (retval=%d)\n", msg, opts.retval);
    } else {
        printf("  [FAIL] %s: expected retval=%d, got %d\n", msg, expected_retval, opts.retval);
        exit(1);
    }
}

void test_packet_ipv6_ext(int prog_fd, const char *msg, int expected_retval, const char *dip_str, __u16 dport) {
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

    struct bpf_test_run_opts opts = {
        .sz = sizeof(struct bpf_test_run_opts),
        .data_in = packet,
        .data_size_in = sizeof(packet),
        .repeat = 1,
    };

    int err = bpf_prog_test_run_opts(prog_fd, &opts);
    if (err) {
        printf("  [FAIL] %s: bpf_prog_test_run_opts failed: %s\n", msg, strerror(errno));
        exit(1);
    }

    if (opts.retval == expected_retval) {
        printf("  [PASS] %s (retval=%d)\n", msg, opts.retval);
    } else {
        printf("  [FAIL] %s: expected retval=%d, got %d\n", msg, expected_retval, opts.retval);
        exit(1);
    }
}

void test_packet_qinq(int prog_fd, const char *msg, int expected_retval, __u16 dport) {
    char packet[128];
    memset(packet, 0, sizeof(packet));

    // Outer Ethernet header + outer VLAN tag (18 bytes)
    // 0-5: Dst MAC (dummy)
    // 6-11: Src MAC (dummy)
    // 12-13: Outer TPID (0x88A8)
    __u16 *p16 = (__u16 *)packet;
    p16[6] = htons(0x88A8);
    // 14-15: Outer TCI (dummy)
    p16[7] = htons(10);
    // 16-17: Inner TPID (0x8100)
    p16[8] = htons(0x8100);
    // 18-19: Inner TCI (dummy)
    p16[9] = htons(20);
    // 20-21: Ethertype (0x0800)
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

    struct bpf_test_run_opts opts = {
        .sz = sizeof(struct bpf_test_run_opts),
        .data_in = packet,
        .data_size_in = sizeof(packet),
        .repeat = 1,
    };

    int err = bpf_prog_test_run_opts(prog_fd, &opts);
    if (err) {
        printf("  [FAIL] %s: bpf_prog_test_run_opts failed: %s\n", msg, strerror(errno));
        exit(1);
    }

    if (opts.retval == expected_retval) {
        printf("  [PASS] %s (retval=%d)\n", msg, opts.retval);
    } else {
        printf("  [FAIL] %s: expected retval=%d, got %d\n", msg, expected_retval, opts.retval);
        exit(1);
    }
}

void test_loop_prevention(int prog_fd, const char *msg) {
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

    struct bpf_test_run_opts opts = {
        .sz = sizeof(struct bpf_test_run_opts),
        .data_in = packet,
        .data_size_in = sizeof(packet),
        .ctx_in = &ctx,
        .ctx_size_in = sizeof(ctx),
        .repeat = 1,
    };

    int err = bpf_prog_test_run_opts(prog_fd, &opts);
    if (err) {
        printf("  [FAIL] %s: bpf_prog_test_run_opts failed: %s\n", msg, strerror(errno));
        exit(1);
    }

    // my_prio defaults to 0, since 0 <= 10, it should return TC_ACT_UNSPEC (-1)
    if (opts.retval == -1) {
        printf("  [PASS] %s (retval=%d)\n", msg, opts.retval);
    } else {
        printf("  [FAIL] %s: expected retval=-1, got %d\n", msg, opts.retval);
        exit(1);
    }
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

    if (bpf_object__load(obj)) {
        fprintf(stderr, "ERROR: loading BPF object file failed\n");
        return 1;
    }

    int map_fd = bpf_object__find_map_fd_by_name(obj, "filter_rules");
    int map_fd_v6 = bpf_object__find_map_fd_by_name(obj, "filter_rules_ipv6");
    int stats_fd = bpf_object__find_map_fd_by_name(obj, "stats_map");
    struct bpf_program *prog = bpf_object__find_program_by_name(obj, "tc_divert_egress");
    if (map_fd < 0 || map_fd_v6 < 0 || stats_fd < 0 || !prog) {
        fprintf(stderr, "ERROR: finding maps or program failed\n");
        return 1;
    }
    int prog_fd = bpf_program__fd(prog);

    printf("Running eBPF C Tests...\n");

    // Case 1: Match and Divert (with Telemetry verification)
    __u64 stats_before = 0, stats_after = 0;
    get_stat(stats_fd, STAT_DIVERTED, &stats_before);

    update_rule(map_fd, 0, 80, MATCH_DST_PORT, 0);
    test_packet(prog_fd, "Match and Divert", 4, 80);

    get_stat(stats_fd, STAT_DIVERTED, &stats_after);
    if (stats_after == stats_before + 1) {
        printf("  [PASS] Telemetry STAT_DIVERTED incremented correctly.\n");
    } else {
        printf("  [FAIL] Telemetry STAT_DIVERTED validation failed. Before: %llu, After: %llu\n", stats_before, stats_after);
        exit(1);
    }

    // Case 2: Match and Sniff
    update_rule(map_fd, 0, 80, MATCH_DST_PORT | MATCH_SNIFF, 0);
    test_packet(prog_fd, "Match and Sniff", -1, 80);

    // Case 3: Match and Drop
    update_rule(map_fd, 0, 80, MATCH_DST_PORT | MATCH_DROP, 0);
    test_packet(prog_fd, "Match and Drop", 2, 80);

    // Case 4: No Match
    update_rule(map_fd, 0, 80, MATCH_DST_PORT, 0);
    test_packet(prog_fd, "No Match (different port)", -1, 8080);

    // Case 5: Match Inversion (Match all NOT port 80)
    update_rule(map_fd, 0, 80, MATCH_DST_PORT, MATCH_DST_PORT);
    test_packet(prog_fd, "Match Inversion - Divert non-80 (port 8080)", 4, 8080);
    test_packet(prog_fd, "Match Inversion - Skip 80 (port 80)", -1, 80);

    // Case 6: IPv6 Match and Divert
    update_rule_ipv6(map_fd_v6, 0, "2001:db8::1", 80, MATCH_DST_IP | MATCH_DST_PORT, 0);
    test_packet_ipv6(prog_fd, "IPv6 Match and Divert", 4, "2001:db8::1", 80);

    // Case 7: IPv6 Match but different IP (No Match)
    test_packet_ipv6(prog_fd, "IPv6 No Match (different IP)", -1, "2001:db8::2", 80);

    // Case 8: IPv6 Match with Hop-by-Hop Extension Header
    update_rule_ipv6(map_fd_v6, 0, "2001:db8::1", 80, MATCH_DST_IP | MATCH_DST_PORT, 0);
    test_packet_ipv6_ext(prog_fd, "IPv6 Match with Hop-by-Hop Ext Header", 4, "2001:db8::1", 80);

    // Case 9: QinQ packet parsing and diversion
    update_rule(map_fd, 0, 80, MATCH_DST_PORT, 0);
    test_packet_qinq(prog_fd, "QinQ Match and Divert", 4, 80);

    // Case 10: IPv4 Subnet/CIDR match (e.g. 192.168.1.0/24 subnet match)
    update_rule_advanced(map_fd, 0,
                         0, 0, // src
                         ntohl(inet_addr("192.168.1.0")), ntohl(inet_addr("255.255.255.0")), // dst subnet
                         0, 0, 80, 80, // dst port 80
                         MATCH_DST_IP | MATCH_DST_PORT, 0);
    test_packet_advanced(prog_fd, "IPv4 Subnet Match (inside /24)", 4, "10.0.0.1", "192.168.1.42", 12345, 80);

    // Case 11: IPv4 Subnet/CIDR mismatch (outside subnet)
    test_packet_advanced(prog_fd, "IPv4 Subnet Mismatch (outside /24)", -1, "10.0.0.1", "192.168.2.42", 12345, 80);

    // Case 12: IPv6 Subnet/CIDR match (e.g. 2001:db8:abcd::/48 subnet match)
    update_rule_ipv6_advanced(map_fd_v6, 0,
                              NULL, NULL, // src
                              "2001:db8:abcd::", "ffff:ffff:ffff::", // dst subnet
                              0, 0, 80, 80, // dst port 80
                              MATCH_DST_IP | MATCH_DST_PORT, 0);
    test_packet_ipv6_advanced(prog_fd, "IPv6 Subnet Match (inside /48)", 4, "::1", "2001:db8:abcd:12:34::56", 12345, 80);

    // Case 13: IPv6 Subnet/CIDR mismatch (outside subnet)
    test_packet_ipv6_advanced(prog_fd, "IPv6 Subnet Mismatch (outside /48)", -1, "::1", "2001:db8:affe:12:34::56", 12345, 80);

    // Case 14: Port range match (e.g. port 8000-8010)
    update_rule_advanced(map_fd, 0,
                         0, 0, 0, 0, // IPs
                         0, 0, 8000, 8010, // dst port range 8000-8010
                         MATCH_DST_PORT, 0);
    test_packet(prog_fd, "Port Range Match (port 8005)", 4, 8005);
    test_packet(prog_fd, "Port Range Mismatch (port 8015)", -1, 8015);

    // Case 15: Loop Prevention check
    test_loop_prevention(prog_fd, "Loop Prevention behavior (ignored)");

    printf("All eBPF C Tests passed!\n");
    bpf_object__close(obj);
    return 0;
}
