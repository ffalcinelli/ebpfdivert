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

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args) {
    return vfprintf(stderr, format, args);
}

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
    __u8  src_ip[16];
    __u8  dst_ip[16];
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

void update_rule(int map_fd, __u32 key, __u16 dst_port, __u16 mask, __u16 invert_mask) {
    struct filter_rule rule = {0};
    rule.dst_port = dst_port;
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
    }
    rule.dst_port = dst_port;
    rule.match_mask = mask | MATCH_ENABLED;
    rule.invert_mask = invert_mask;
    if (bpf_map_update_elem(map_fd, &key, &rule, BPF_ANY)) {
        fprintf(stderr, "ERROR: updating filter_rules_ipv6 map failed: %s\n", strerror(errno));
        exit(1);
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
    struct bpf_program *prog = bpf_object__find_program_by_name(obj, "tc_divert_egress");
    if (map_fd < 0 || map_fd_v6 < 0 || !prog) {
        fprintf(stderr, "ERROR: finding maps or program failed\n");
        return 1;
    }
    int prog_fd = bpf_program__fd(prog);

    printf("Running eBPF C Tests...\n");

    // Case 1: Match and Divert
    update_rule(map_fd, 0, 80, MATCH_DST_PORT, 0);
    test_packet(prog_fd, "Match and Divert", 4, 80);

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

    printf("All eBPF C Tests passed!\n");
    bpf_object__close(obj);
    return 0;
}
