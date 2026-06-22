// SPDX-License-Identifier: GPL-2.0-or-later OR LGPL-3.0-or-later
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <linux/pkt_cls.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <ifaddrs.h>
#include <sys/mman.h>
#include "ebpfdivert.h"

static void cleanup_pinned_resources(void) {
    const char *map_names[] = {"filter_rules", "filter_rules_ipv6", "stats_map", "config_map", "pcap_ringbuf"};
    for (int i = 0; i < 5; i++) {
        char pin_path[256];
        snprintf(pin_path, sizeof(pin_path), "/sys/fs/bpf/ebpfdivert/%s", map_names[i]);
        unlink(pin_path);
    }
    rmdir("/sys/fs/bpf/ebpfdivert");
}

static int attach_tc_hooks(int ifindex, struct bpf_program *prog_ingress, struct bpf_program *prog_egress) {
    DECLARE_LIBBPF_OPTS(bpf_tc_hook, hook_ingress,
        .sz = sizeof(struct bpf_tc_hook),
        .ifindex = ifindex,
        .attach_point = BPF_TC_INGRESS
    );

    bpf_tc_hook_create(&hook_ingress);

    DECLARE_LIBBPF_OPTS(bpf_tc_opts, opts_ingress,
        .sz = sizeof(struct bpf_tc_opts),
        .prog_fd = bpf_program__fd(prog_ingress)
    );

    int err = bpf_tc_attach(&hook_ingress, &opts_ingress);
    if (err && err != -EEXIST) {
        fprintf(stderr, "ERROR: attaching ingress program to ifindex %d failed: %s\n", ifindex, strerror(-err));
        bpf_tc_hook_destroy(&hook_ingress);
        return -1;
    }

    DECLARE_LIBBPF_OPTS(bpf_tc_hook, hook_egress,
        .sz = sizeof(struct bpf_tc_hook),
        .ifindex = ifindex,
        .attach_point = BPF_TC_EGRESS
    );

    bpf_tc_hook_create(&hook_egress);

    DECLARE_LIBBPF_OPTS(bpf_tc_opts, opts_egress,
        .sz = sizeof(struct bpf_tc_opts),
        .prog_fd = bpf_program__fd(prog_egress)
    );

    err = bpf_tc_attach(&hook_egress, &opts_egress);
    if (err && err != -EEXIST) {
        fprintf(stderr, "ERROR: attaching egress program to ifindex %d failed: %s\n", ifindex, strerror(-err));
        DECLARE_LIBBPF_OPTS(bpf_tc_hook, hook_ingress_del,
            .sz = sizeof(struct bpf_tc_hook),
            .ifindex = ifindex,
            .attach_point = BPF_TC_INGRESS
        );
        bpf_tc_detach(&hook_ingress_del, &opts_ingress);
        bpf_tc_hook_destroy(&hook_ingress_del);
        bpf_tc_hook_destroy(&hook_egress);
        return -1;
    }

    return 0;
}

static int detach_tc_hooks(int ifindex) {
    DECLARE_LIBBPF_OPTS(bpf_tc_hook, hook,
        .sz = sizeof(struct bpf_tc_hook),
        .ifindex = ifindex,
        .attach_point = BPF_TC_INGRESS | BPF_TC_EGRESS
    );
    int err = bpf_tc_hook_destroy(&hook);
    return err;
}

int ebpfdivert_load(const char *ifname, const char *obj_path, uint32_t priority) {
    int attach_all = (ifname == NULL || strcmp(ifname, "all") == 0);
    int ifindex = 0;
    if (!attach_all) {
        ifindex = if_nametoindex(ifname);
        if (ifindex == 0) {
            fprintf(stderr, "ERROR: interface '%s' not found\n", ifname);
            return -1;
        }
    }

    struct bpf_object *obj = bpf_object__open_file(obj_path, NULL);
    if (!obj) {
        fprintf(stderr, "ERROR: opening BPF object file '%s' failed\n", obj_path);
        return -1;
    }

    if (bpf_object__load(obj)) {
        fprintf(stderr, "ERROR: loading BPF object file failed\n");
        bpf_object__close(obj);
        return -1;
    }

    mkdir("/sys/fs/bpf/ebpfdivert", 0755);

    const char *map_names[] = {"filter_rules", "filter_rules_ipv6", "stats_map", "config_map", "pcap_ringbuf"};
    for (int i = 0; i < 5; i++) {
        struct bpf_map *map = bpf_object__find_map_by_name(obj, map_names[i]);
        if (map) {
            char pin_path[256];
            snprintf(pin_path, sizeof(pin_path), "/sys/fs/bpf/ebpfdivert/%s", map_names[i]);
            unlink(pin_path);
            if (bpf_map__pin(map, pin_path)) {
                fprintf(stderr, "WARNING: pinning map '%s' failed: %s\n", map_names[i], strerror(errno));
            }
        }
    }

    struct bpf_map *config_map = bpf_object__find_map_by_name(obj, "config_map");
    if (config_map) {
        __u32 key = 0;
        struct divert_config config = {
            .priority = priority,
            .snaplen = 2048,
            .loop_prevention_mark = 0x4D490000
        };
        int map_fd = bpf_map__fd(config_map);
        if (map_fd >= 0) {
            if (bpf_map_update_elem(map_fd, &key, &config, BPF_ANY)) {
                fprintf(stderr, "WARNING: setting config in config_map failed: %s\n", strerror(errno));
            }
        }
    }

    struct bpf_program *prog_ingress = bpf_object__find_program_by_name(obj, "tc_divert_ingress");
    struct bpf_program *prog_egress = bpf_object__find_program_by_name(obj, "tc_divert_egress");
    if (!prog_ingress || !prog_egress) {
        fprintf(stderr, "ERROR: programs not found in object file\n");
        cleanup_pinned_resources();
        bpf_object__close(obj);
        return -1;
    }

    int attached_count = 0;
    if (attach_all) {
        struct ifaddrs *ifaddr, *ifa;
        if (getifaddrs(&ifaddr) == -1) {
            fprintf(stderr, "ERROR: getifaddrs failed: %s\n", strerror(errno));
            cleanup_pinned_resources();
            bpf_object__close(obj);
            return -1;
        }

        for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
            if (ifa->ifa_addr == NULL) continue;
            if (ifa->ifa_addr->sa_family != AF_PACKET) continue;

            unsigned int flags = ifa->ifa_flags;
            if (strcmp(ifa->ifa_name, "lo") == 0) continue;
            if (!(flags & IFF_UP)) continue;

            int idx = if_nametoindex(ifa->ifa_name);
            if (idx == 0) continue;

            if (attach_tc_hooks(idx, prog_ingress, prog_egress) == 0) {
                attached_count++;
            }
        }
        freeifaddrs(ifaddr);
        if (attached_count == 0) {
            fprintf(stderr, "ERROR: no active network interfaces found to attach to\n");
            cleanup_pinned_resources();
            bpf_object__close(obj);
            return -1;
        }
        printf("Successfully loaded and attached eBPFDivert to %d interfaces (Ingress & Egress)\n", attached_count);
    } else {
        if (attach_tc_hooks(ifindex, prog_ingress, prog_egress) != 0) {
            cleanup_pinned_resources();
            bpf_object__close(obj);
            return -1;
        }
        printf("Successfully loaded and attached eBPFDivert to '%s' (Ingress & Egress)\n", ifname);
    }

    bpf_object__close(obj);
    return 0;
}

int ebpfdivert_unload(const char *ifname) {
    int detach_all = (ifname == NULL || strcmp(ifname, "all") == 0);

    if (detach_all) {
        struct ifaddrs *ifaddr, *ifa;
        if (getifaddrs(&ifaddr) == -1) {
            fprintf(stderr, "ERROR: getifaddrs failed: %s\n", strerror(errno));
            return -1;
        }

        for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
            if (ifa->ifa_addr == NULL) continue;
            if (ifa->ifa_addr->sa_family != AF_PACKET) continue;

            int idx = if_nametoindex(ifa->ifa_name);
            if (idx == 0) continue;

            detach_tc_hooks(idx);
        }
        freeifaddrs(ifaddr);
        cleanup_pinned_resources();
        printf("Successfully unloaded and detached eBPFDivert from all interfaces\n");
    } else {
        int ifindex = if_nametoindex(ifname);
        if (ifindex == 0) {
            fprintf(stderr, "ERROR: interface '%s' not found\n", ifname);
            return -1;
        }
        detach_tc_hooks(ifindex);
        cleanup_pinned_resources();
        printf("Successfully unloaded and detached eBPFDivert from '%s'\n", ifname);
    }
    return 0;
}

int ebpfdivert_rules_clear(void) {
    int map_fd = bpf_obj_get("/sys/fs/bpf/ebpfdivert/filter_rules");
    int map_fd_v6 = bpf_obj_get("/sys/fs/bpf/ebpfdivert/filter_rules_ipv6");
    if (map_fd < 0 || map_fd_v6 < 0) {
        fprintf(stderr, "ERROR: eBPFDivert maps not found. Is the driver loaded?\n");
        if (map_fd >= 0) close(map_fd);
        if (map_fd_v6 >= 0) close(map_fd_v6);
        return -1;
    }

    struct filter_rule rule = {0};
    for (__u32 i = 0; i < MAX_RULES; i++) {
        bpf_map_update_elem(map_fd, &i, &rule, BPF_ANY);
    }

    struct filter_rule_ipv6 rule_v6 = {0};
    for (__u32 i = 0; i < MAX_RULES; i++) {
        bpf_map_update_elem(map_fd_v6, &i, &rule_v6, BPF_ANY);
    }

    close(map_fd);
    close(map_fd_v6);
    printf("Successfully cleared all filter rules\n");
    return 0;
}

int ebpfdivert_rules_list(void) {
    int map_fd = bpf_obj_get("/sys/fs/bpf/ebpfdivert/filter_rules");
    int map_fd_v6 = bpf_obj_get("/sys/fs/bpf/ebpfdivert/filter_rules_ipv6");
    if (map_fd < 0 || map_fd_v6 < 0) {
        fprintf(stderr, "ERROR: eBPFDivert maps not found. Is the driver loaded?\n");
        if (map_fd >= 0) close(map_fd);
        if (map_fd_v6 >= 0) close(map_fd_v6);
        return -1;
    }

    printf("IPv4/Generic Rules:\n");
    printf("IDX | Proto | Action | Dst Port Range | Dst IP/Mask\n");
    printf("---------------------------------------------------\n");
    for (__u32 i = 0; i < MAX_RULES; i++) {
        struct filter_rule rule;
        if (bpf_map_lookup_elem(map_fd, &i, &rule) == 0) {
            if (!(rule.match_mask & MATCH_ENABLED)) continue;
            
            char proto_str[16] = "ANY";
            if (rule.match_mask & MATCH_PROTO) {
                if (rule.proto == 6) strcpy(proto_str, "TCP");
                else if (rule.proto == 1) strcpy(proto_str, "ICMP");
                else if (rule.proto == 17) strcpy(proto_str, "UDP");
                else snprintf(proto_str, sizeof(proto_str), "%u", rule.proto);
            }

            char action_str[16] = "DIVERT";
            if (rule.match_mask & MATCH_DROP) strcpy(action_str, "DROP");
            else if (rule.match_mask & MATCH_SNIFF) strcpy(action_str, "SNIFF");

            char port_str[32] = "ANY";
            if (rule.match_mask & MATCH_DST_PORT) {
                if (rule.proto == 1) {
                    snprintf(port_str, sizeof(port_str), "Type:%u Code:%u", rule.icmp_type_start, rule.icmp_code_start);
                } else {
                    snprintf(port_str, sizeof(port_str), "%u-%u", rule.dst_port_start, rule.dst_port_end);
                }
            }

            char ip_str[64] = "ANY";
            if (rule.match_mask & MATCH_DST_IP) {
                struct in_addr ip_addr = { .s_addr = htonl(rule.dst_ip) };
                struct in_addr mask_addr = { .s_addr = htonl(rule.dst_mask) };
                snprintf(ip_str, sizeof(ip_str), "%s/%s", inet_ntoa(ip_addr), inet_ntoa(mask_addr));
            }

            printf("%-3u | %-5s | %-6s | %-14s | %s\n", i, proto_str, action_str, port_str, ip_str);
        }
    }

    printf("\nIPv6-specific Rules:\n");
    printf("IDX | Proto | Action | Dst Port Range | Dst IP/Mask\n");
    printf("---------------------------------------------------\n");
    for (__u32 i = 0; i < MAX_RULES; i++) {
        struct filter_rule_ipv6 rule;
        if (bpf_map_lookup_elem(map_fd_v6, &i, &rule) == 0) {
            if (!(rule.match_mask & MATCH_ENABLED)) continue;
            
            char proto_str[16] = "ANY";
            if (rule.match_mask & MATCH_PROTO) {
                if (rule.proto == 6) strcpy(proto_str, "TCP");
                else if (rule.proto == 17) strcpy(proto_str, "UDP");
                else if (rule.proto == 58) strcpy(proto_str, "ICMPv6");
                else snprintf(proto_str, sizeof(proto_str), "%u", rule.proto);
            }

            char action_str[16] = "DIVERT";
            if (rule.match_mask & MATCH_DROP) strcpy(action_str, "DROP");
            else if (rule.match_mask & MATCH_SNIFF) strcpy(action_str, "SNIFF");

            char port_str[32] = "ANY";
            if (rule.match_mask & MATCH_DST_PORT) {
                if (rule.proto == 58) {
                    snprintf(port_str, sizeof(port_str), "Type:%u Code:%u", rule.icmp_type_start, rule.icmp_code_start);
                } else {
                    snprintf(port_str, sizeof(port_str), "%u-%u", rule.dst_port_start, rule.dst_port_end);
                }
            }

            char ip_str[128] = "ANY";
            if (rule.match_mask & MATCH_DST_IP) {
                char ip_addr_str[64];
                char mask_addr_str[64];
                inet_ntop(AF_INET6, rule.dst_ip, ip_addr_str, sizeof(ip_addr_str));
                inet_ntop(AF_INET6, rule.dst_mask, mask_addr_str, sizeof(mask_addr_str));
                snprintf(ip_str, sizeof(ip_str), "%s/%s", ip_addr_str, mask_addr_str);
            }

            printf("%-3u | %-5s | %-6s | %-14s | %s\n", i, proto_str, action_str, port_str, ip_str);
        }
    }

    close(map_fd);
    close(map_fd_v6);
    return 0;
}

int ebpfdivert_rules_add(int idx, const char *proto, const char *ip_cidr, const char *port_range, const char *action) {
    if (!proto || !ip_cidr || !port_range || !action) {
        fprintf(stderr, "ERROR: invalid NULL argument to ebpfdivert_rules_add\n");
        return -1;
    }

    int map_fd = bpf_obj_get("/sys/fs/bpf/ebpfdivert/filter_rules");
    int map_fd_v6 = bpf_obj_get("/sys/fs/bpf/ebpfdivert/filter_rules_ipv6");
    if (map_fd < 0 || map_fd_v6 < 0) {
        fprintf(stderr, "ERROR: eBPFDivert maps not found. Is the driver loaded?\n");
        if (map_fd >= 0) close(map_fd);
        if (map_fd_v6 >= 0) close(map_fd_v6);
        return -1;
    }

    if (idx < 0 || idx >= MAX_RULES) {
        fprintf(stderr, "ERROR: rule index must be between 0 and %d\n", MAX_RULES - 1);
        close(map_fd);
        close(map_fd_v6);
        return -1;
    }

    int is_ipv6 = 0;
    if (ip_cidr && strchr(ip_cidr, ':')) {
        is_ipv6 = 1;
    }
    if (strcmp(proto, "icmpv6") == 0) {
        is_ipv6 = 1;
    }

    if (!is_ipv6) {
        struct filter_rule rule = {0};
        rule.match_mask = MATCH_ENABLED;

        if (strcmp(proto, "any") != 0) {
            rule.match_mask |= MATCH_PROTO;
            if (strcmp(proto, "tcp") == 0) rule.proto = 6;
            else if (strcmp(proto, "udp") == 0) rule.proto = 17;
            else if (strcmp(proto, "icmp") == 0) rule.proto = 1;
            else rule.proto = atoi(proto);
        }

        if (strcmp(action, "drop") == 0) rule.match_mask |= MATCH_DROP;
        else if (strcmp(action, "sniff") == 0) rule.match_mask |= MATCH_SNIFF;

        if (strcmp(ip_cidr, "any") != 0) {
            rule.match_mask |= MATCH_DST_IP;
            char ip_str[64];
            strncpy(ip_str, ip_cidr, sizeof(ip_str));
            char *slash = strchr(ip_str, '/');
            int bits = 32;
            if (slash) {
                *slash = '\0';
                bits = atoi(slash + 1);
            }
            unsigned long addr = inet_addr(ip_str);
            if (addr == INADDR_NONE) {
                fprintf(stderr, "ERROR: invalid IP address '%s'\n", ip_str);
                close(map_fd);
                close(map_fd_v6);
                return -1;
            }
            if (bits < 0 || bits > 32) {
                fprintf(stderr, "ERROR: invalid CIDR mask bits %d\n", bits);
                close(map_fd);
                close(map_fd_v6);
                return -1;
            }
            rule.dst_ip = ntohl(addr);
            if (bits >= 32) rule.dst_mask = 0xFFFFFFFF;
            else if (bits <= 0) rule.dst_mask = 0;
            else rule.dst_mask = (0xFFFFFFFF << (32 - bits));
        }

        if (strcmp(port_range, "any") != 0) {
            rule.match_mask |= MATCH_DST_PORT;
            if (rule.proto == 1) {
                char pr_str[32];
                strncpy(pr_str, port_range, sizeof(pr_str));
                char *slash = strchr(pr_str, '/');
                int type = atoi(pr_str);
                int code = 0;
                if (slash) {
                    code = atoi(slash + 1);
                }
                rule.icmp_type_start = type;
                rule.icmp_type_end = type;
                rule.icmp_code_start = code;
                rule.icmp_code_end = code;
            } else {
                char pr_str[32];
                strncpy(pr_str, port_range, sizeof(pr_str));
                char *dash = strchr(pr_str, '-');
                if (dash) {
                    *dash = '\0';
                    rule.dst_port_start = atoi(pr_str);
                    rule.dst_port_end = atoi(dash + 1);
                } else {
                    int p = atoi(pr_str);
                    rule.dst_port_start = p;
                    rule.dst_port_end = p;
                }
            }
        }

        if (bpf_map_update_elem(map_fd, &idx, &rule, BPF_ANY)) {
            fprintf(stderr, "ERROR: updating filter_rules map failed: %s\n", strerror(errno));
            close(map_fd);
            close(map_fd_v6);
            return -1;
        }
    } else {
        struct filter_rule_ipv6 rule = {0};
        rule.match_mask = MATCH_ENABLED;

        if (strcmp(proto, "any") != 0) {
            rule.match_mask |= MATCH_PROTO;
            if (strcmp(proto, "tcp") == 0) rule.proto = 6;
            else if (strcmp(proto, "udp") == 0) rule.proto = 17;
            else if (strcmp(proto, "icmpv6") == 0) rule.proto = 58;
            else rule.proto = atoi(proto);
        }

        if (strcmp(action, "drop") == 0) rule.match_mask |= MATCH_DROP;
        else if (strcmp(action, "sniff") == 0) rule.match_mask |= MATCH_SNIFF;

        if (strcmp(ip_cidr, "any") != 0) {
            rule.match_mask |= MATCH_DST_IP;
            char ip_str[128];
            strncpy(ip_str, ip_cidr, sizeof(ip_str));
            char *slash = strchr(ip_str, '/');
            int bits = 128;
            if (slash) {
                *slash = '\0';
                bits = atoi(slash + 1);
            }
            if (inet_pton(AF_INET6, ip_str, rule.dst_ip) != 1) {
                fprintf(stderr, "ERROR: invalid IPv6 address '%s'\n", ip_str);
                close(map_fd);
                close(map_fd_v6);
                return -1;
            }
            if (bits < 0 || bits > 128) {
                fprintf(stderr, "ERROR: invalid IPv6 CIDR mask bits %d\n", bits);
                close(map_fd);
                close(map_fd_v6);
                return -1;
            }
            for (int i = 0; i < 16; i++) {
                if (bits >= 8) {
                    rule.dst_mask[i] = 0xFF;
                    bits -= 8;
                } else if (bits > 0) {
                    rule.dst_mask[i] = (0xFF << (8 - bits));
                    bits = 0;
                } else {
                    rule.dst_mask[i] = 0;
                }
            }
        }

        if (strcmp(port_range, "any") != 0) {
            rule.match_mask |= MATCH_DST_PORT;
            if (rule.proto == 58) {
                char pr_str[32];
                strncpy(pr_str, port_range, sizeof(pr_str));
                char *slash = strchr(pr_str, '/');
                int type = atoi(pr_str);
                int code = 0;
                if (slash) {
                    code = atoi(slash + 1);
                }
                rule.icmp_type_start = type;
                rule.icmp_type_end = type;
                rule.icmp_code_start = code;
                rule.icmp_code_end = code;
            } else {
                char pr_str[32];
                strncpy(pr_str, port_range, sizeof(pr_str));
                char *dash = strchr(pr_str, '-');
                if (dash) {
                    *dash = '\0';
                    rule.dst_port_start = atoi(pr_str);
                    rule.dst_port_end = atoi(dash + 1);
                } else {
                    int p = atoi(pr_str);
                    rule.dst_port_start = p;
                    rule.dst_port_end = p;
                }
            }
        }

        if (bpf_map_update_elem(map_fd_v6, &idx, &rule, BPF_ANY)) {
            fprintf(stderr, "ERROR: updating filter_rules_ipv6 map failed: %s\n", strerror(errno));
            close(map_fd);
            close(map_fd_v6);
            return -1;
        }
    }

    close(map_fd);
    close(map_fd_v6);
    printf("Successfully added rule at index %d\n", idx);
    return 0;
}

int ebpfdivert_get_stats(uint64_t *stats, int stats_len) {
    int stats_fd = bpf_obj_get("/sys/fs/bpf/ebpfdivert/stats_map");
    if (stats_fd < 0) {
        return -1;
    }

    int num_cpus = libbpf_num_possible_cpus();
    __u64 values[num_cpus];

    for (__u32 key = 0; key < 5 && key < (__u32)stats_len; key++) {
        memset(values, 0, sizeof(values));
        uint64_t total = 0;
        if (bpf_map_lookup_elem(stats_fd, &key, values) == 0) {
            for (int i = 0; i < num_cpus; i++) {
                total += values[i];
            }
        }
        stats[key] = total;
    }

    close(stats_fd);
    return 0;
}

struct if_sock_entry {
    int ifindex;
    int sock;
    uint8_t *tx_ring;
    uint32_t tx_index;
};

struct ebpfdivert_handle {
    struct ring_buffer *rb;
    int ringbuf_fd;
    uint32_t priority;
    
    struct divert_packet_buffer *curr_buf;
    size_t curr_buf_len;
    int curr_received;

    // Cache of interface-specific raw sockets for TX ring injection
    struct if_sock_entry socks[16];
    int socks_count;
};

static int ebpfdivert_rb_callback(void *ctx, void *data, size_t size) {
    struct ebpfdivert_handle *h = ctx;
    if (!h) return 0;
    
    if (h->curr_received) {
        return -1;
    }
    
    size_t to_copy = (size < h->curr_buf_len) ? size : h->curr_buf_len;
    memcpy(h->curr_buf, data, to_copy);
    h->curr_received = 1;
    return 0;
}

ebpfdivert_handle_t *ebpfdivert_open(uint32_t priority) {
    struct ebpfdivert_handle *h = calloc(1, sizeof(struct ebpfdivert_handle));
    if (!h) return NULL;
    
    h->priority = priority;
    h->ringbuf_fd = -1;
    
    h->ringbuf_fd = bpf_obj_get("/sys/fs/bpf/ebpfdivert/pcap_ringbuf");
    if (h->ringbuf_fd < 0) {
        fprintf(stderr, "ERROR: pcap_ringbuf map not found. Is the driver loaded?\n");
        free(h);
        return NULL;
    }
    
    h->rb = ring_buffer__new(h->ringbuf_fd, ebpfdivert_rb_callback, h, NULL);
    if (!h->rb) {
        fprintf(stderr, "ERROR: failed to create ring buffer consumer\n");
        close(h->ringbuf_fd);
        free(h);
        return NULL;
    }
    
    h->socks_count = 0;
    return h;
}

int ebpfdivert_recv(ebpfdivert_handle_t *h, struct divert_packet_buffer *buf, size_t buf_len, int timeout_ms) {
    if (!h || !buf) return -EINVAL;
    
    h->curr_buf = buf;
    h->curr_buf_len = buf_len;
    h->curr_received = 0;
    
    int ret = ring_buffer__poll(h->rb, timeout_ms);
    
    h->curr_buf = NULL;
    h->curr_buf_len = 0;
    
    if (h->curr_received) {
        return 0;
    }
    
    if (ret < 0) {
        if (ret == -EINTR || ret == -1) {
            if (h->curr_received) return 0;
        }
        return ret;
    }
    
    return -EAGAIN;
}

int ebpfdivert_send(ebpfdivert_handle_t *h, const struct divert_packet_buffer *buf) {
    if (!h || !buf) return -EINVAL;
    
    int ifindex = buf->header.ifindex;
    if (ifindex <= 0) return -EINVAL;
    
    int sock_idx = -1;
    for (int i = 0; i < h->socks_count; i++) {
        if (h->socks[i].ifindex == ifindex) {
            sock_idx = i;
            break;
        }
    }
    
    if (sock_idx == -1) {
        if (h->socks_count >= 16) {
            return -ENOSPC;
        }
        int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
        if (sock < 0) {
            return -errno;
        }
        
        uint32_t mark = 0x4D490000 | (h->priority & 0xFFFF);
        if (setsockopt(sock, SOL_SOCKET, SO_MARK, &mark, sizeof(mark)) < 0) {
            close(sock);
            return -errno;
        }
        
        struct sockaddr_ll sll;
        memset(&sll, 0, sizeof(sll));
        sll.sll_family = AF_PACKET;
        sll.sll_ifindex = ifindex;
        sll.sll_protocol = htons(ETH_P_ALL);
        if (bind(sock, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
            close(sock);
            return -errno;
        }
        
        uint8_t *tx_ring = NULL;
        struct tpacket_req req = {
            .tp_block_size = 16384,
            .tp_block_nr = 8,
            .tp_frame_size = 2048,
            .tp_frame_nr = 64
        };
        if (setsockopt(sock, SOL_PACKET, PACKET_TX_RING, &req, sizeof(req)) == 0) {
            size_t ring_len = req.tp_block_size * req.tp_block_nr;
            tx_ring = mmap(NULL, ring_len, PROT_READ | PROT_WRITE, MAP_SHARED, sock, 0);
            if (tx_ring == MAP_FAILED) {
                tx_ring = NULL;
            }
        }
        
        sock_idx = h->socks_count;
        h->socks[sock_idx].ifindex = ifindex;
        h->socks[sock_idx].sock = sock;
        h->socks[sock_idx].tx_ring = tx_ring;
        h->socks[sock_idx].tx_index = 0;
        h->socks_count++;
    }
    
    int sock = h->socks[sock_idx].sock;
    uint8_t *tx_ring = h->socks[sock_idx].tx_ring;
    
    if (tx_ring) {
        uint32_t frame_size = 2048;
        uint32_t frame_nr = 64;
        uint32_t idx = h->socks[sock_idx].tx_index;
        
        struct tpacket_hdr *hdr = (struct tpacket_hdr *)(tx_ring + idx * frame_size);
        
        int retries = 1000;
        while (hdr->tp_status != TP_STATUS_AVAILABLE && retries > 0) {
            usleep(1);
            retries--;
        }
        
        if (hdr->tp_status != TP_STATUS_AVAILABLE) {
            goto fallback_send;
        }
        
        uint8_t *frame_data = (uint8_t *)hdr + TPACKET_HDRLEN;
        size_t to_copy = buf->header.pkt_len;
        if (to_copy > 2048 - TPACKET_HDRLEN) {
            to_copy = 2048 - TPACKET_HDRLEN;
        }
        memcpy(frame_data, buf->data, to_copy);
        
        hdr->tp_len = to_copy;
        hdr->tp_status = TP_STATUS_SENDING;
        
        ssize_t sent = send(sock, NULL, 0, MSG_DONTWAIT);
        if (sent < 0 && errno != EAGAIN && errno != ENOBUFS) {
            return -errno;
        }
        
        h->socks[sock_idx].tx_index = (idx + 1) % frame_nr;
    } else {
    fallback_send: ;
        ssize_t sent = send(sock, buf->data, buf->header.pkt_len, 0);
        if (sent < 0) {
            return -errno;
        }
    }
    
    return 0;
}

void ebpfdivert_close(ebpfdivert_handle_t *h) {
    if (!h) return;
    for (int i = 0; i < h->socks_count; i++) {
        if (h->socks[i].tx_ring) {
            munmap(h->socks[i].tx_ring, 16384 * 8);
        }
        close(h->socks[i].sock);
    }
    if (h->rb) {
        ring_buffer__free(h->rb);
    }
    if (h->ringbuf_fd >= 0) {
        close(h->ringbuf_fd);
    }
    free(h);
}
