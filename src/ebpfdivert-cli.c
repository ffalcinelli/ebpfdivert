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
#include "ebpfdivert_shared.h"

void print_usage(const char *prog_name) {
    printf("Usage: %s <command> [args]\n", prog_name);
    printf("Commands:\n");
    printf("  load <interface> [bpf_object_path]  Attach driver to interface\n");
    printf("  unload <interface>                  Detach driver from interface\n");
    printf("  stats                               Print packet telemetry stats\n");
    printf("  rules list                          List all active rules\n");
    printf("  rules clear                         Clear all active rules\n");
    printf("  rules add <idx> <proto> <dst_ip/mask> <dst_port_range> <action>\n");
    printf("                                      Add a new rule (idx 0-%d)\n", MAX_RULES - 1);
    printf("                                      proto: tcp, udp, icmp, icmpv6, any\n");
    printf("                                      dst_ip/mask: e.g. 192.168.1.0/24, any\n");
    printf("                                      dst_port_range: e.g. 80, 8000-8010, type/code for icmp, any\n");
    printf("                                      action: divert, drop, sniff\n");
}

int attach_tc(const char *ifname, const char *obj_path) {
    int ifindex = if_nametoindex(ifname);
    if (ifindex == 0) {
        fprintf(stderr, "ERROR: interface '%s' not found\n", ifname);
        return -1;
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

    struct bpf_program *prog_ingress = bpf_object__find_program_by_name(obj, "tc_divert_ingress");
    struct bpf_program *prog_egress = bpf_object__find_program_by_name(obj, "tc_divert_egress");
    if (!prog_ingress || !prog_egress) {
        fprintf(stderr, "ERROR: programs not found in object file\n");
        bpf_object__close(obj);
        return -1;
    }

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
    if (err) {
        fprintf(stderr, "ERROR: attaching ingress program failed: %s\n", strerror(-err));
        bpf_object__close(obj);
        return -1;
    }

    DECLARE_LIBBPF_OPTS(bpf_tc_hook, hook_egress,
        .sz = sizeof(struct bpf_tc_hook),
        .ifindex = ifindex,
        .attach_point = BPF_TC_EGRESS
    );

    DECLARE_LIBBPF_OPTS(bpf_tc_opts, opts_egress,
        .sz = sizeof(struct bpf_tc_opts),
        .prog_fd = bpf_program__fd(prog_egress)
    );

    err = bpf_tc_attach(&hook_egress, &opts_egress);
    if (err) {
        fprintf(stderr, "ERROR: attaching egress program failed: %s\n", strerror(-err));
        bpf_tc_detach(&hook_ingress, &opts_ingress);
        bpf_object__close(obj);
        return -1;
    }

    printf("Successfully loaded and attached eBPFDivert to '%s' (Ingress & Egress)\n", ifname);
    bpf_object__close(obj);
    return 0;
}

int detach_tc(const char *ifname) {
    int ifindex = if_nametoindex(ifname);
    if (ifindex == 0) {
        fprintf(stderr, "ERROR: interface '%s' not found\n", ifname);
        return -1;
    }

    DECLARE_LIBBPF_OPTS(bpf_tc_hook, hook,
        .sz = sizeof(struct bpf_tc_hook),
        .ifindex = ifindex,
        .attach_point = BPF_TC_INGRESS | BPF_TC_EGRESS
    );

    int err = bpf_tc_hook_destroy(&hook);
    if (err && err != -ENOENT) {
        fprintf(stderr, "WARNING: destroying hook failed: %s\n", strerror(-err));
    }

    const char *map_names[] = {"filter_rules", "filter_rules_ipv6", "stats_map", "config_map", "pcap_ringbuf"};
    for (int i = 0; i < 5; i++) {
        char pin_path[256];
        snprintf(pin_path, sizeof(pin_path), "/sys/fs/bpf/ebpfdivert/%s", map_names[i]);
        unlink(pin_path);
    }
    rmdir("/sys/fs/bpf/ebpfdivert");

    printf("Successfully unloaded and detached eBPFDivert from '%s'\n", ifname);
    return 0;
}

int rules_clear() {
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

int rules_list() {
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

int rules_add(int idx, const char *proto, const char *ip_cidr, const char *port_range, const char *action) {
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
            rule.dst_ip = ntohl(inet_addr(ip_str));
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
            inet_pton(AF_INET6, ip_str, rule.dst_ip);
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

int get_stats() {
    int stats_fd = bpf_obj_get("/sys/fs/bpf/ebpfdivert/stats_map");
    if (stats_fd < 0) {
        fprintf(stderr, "ERROR: eBPFDivert stats map not found. Is the driver loaded?\n");
        return -1;
    }

    const char *stat_names[] = {
        "Diverted",
        "Dropped",
        "Sniffed",
        "Parsing Errors",
        "Ringbuf Full"
    };

    printf("eBPFDivert Statistics:\n");
    printf("Metric          | Value\n");
    printf("---------------------------\n");
    
    int num_cpus = libbpf_num_possible_cpus();
    __u64 values[num_cpus];

    for (__u32 key = 0; key < 5; key++) {
        memset(values, 0, sizeof(values));
        __u64 total = 0;
        if (bpf_map_lookup_elem(stats_fd, &key, values) == 0) {
            for (int i = 0; i < num_cpus; i++) {
                total += values[i];
            }
        }
        printf("%-15s | %llu\n", stat_names[key], total);
    }

    close(stats_fd);
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }

    const char *cmd = argv[1];

    if (strcmp(cmd, "load") == 0) {
        if (argc < 3) {
            fprintf(stderr, "Usage: %s load <interface> [bpf_object_path]\n", argv[0]);
            return 1;
        }
        const char *ifname = argv[2];
        const char *obj_path = (argc >= 4) ? argv[3] : "ebpfdivert.bpf.o";
        return attach_tc(ifname, obj_path) ? 1 : 0;
    } else if (strcmp(cmd, "unload") == 0) {
        if (argc < 3) {
            fprintf(stderr, "Usage: %s unload <interface>\n", argv[0]);
            return 1;
        }
        const char *ifname = argv[2];
        return detach_tc(ifname) ? 1 : 0;
    } else if (strcmp(cmd, "stats") == 0) {
        return get_stats() ? 1 : 0;
    } else if (strcmp(cmd, "rules") == 0) {
        if (argc < 3) {
            fprintf(stderr, "Usage: %s rules <list|clear|add> [args]\n", argv[0]);
            return 1;
        }
        const char *subcmd = argv[2];
        if (strcmp(subcmd, "list") == 0) {
            return rules_list() ? 1 : 0;
        } else if (strcmp(subcmd, "clear") == 0) {
            return rules_clear() ? 1 : 0;
        } else if (strcmp(subcmd, "add") == 0) {
            if (argc < 8) {
                fprintf(stderr, "Usage: %s rules add <idx> <proto> <dst_ip/mask> <dst_port_range> <action>\n", argv[0]);
                return 1;
            }
            int idx = atoi(argv[3]);
            const char *proto = argv[4];
            const char *ip_cidr = argv[5];
            const char *port_range = argv[6];
            const char *action = argv[7];
            return rules_add(idx, proto, ip_cidr, port_range, action) ? 1 : 0;
        } else {
            fprintf(stderr, "ERROR: unknown rules subcommand '%s'\n", subcmd);
            return 1;
        }
    } else {
        fprintf(stderr, "ERROR: unknown command '%s'\n", cmd);
        print_usage(argv[0]);
        return 1;
    }
}
