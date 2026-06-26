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

#include <stdarg.h>

static ebpfdivert_print_fn_t ebpfdivert_user_print_fn = NULL;

void ebpfdivert_set_print(ebpfdivert_print_fn_t print_fn) {
    ebpfdivert_user_print_fn = print_fn;
}

const char *ebpfdivert_version(void) {
    return EBPFDIVERT_VERSION;
}

static int default_print_fn(enum ebpfdivert_print_level level, const char *format, va_list args) {
    if (level <= EBPFDIVERT_WARN) {
        return vfprintf(stderr, format, args);
    }
    return 0;
}

static int pr_log(enum ebpfdivert_print_level level, const char *format, ...) {
    va_list args;
    int err;
    va_start(args, format);
    if (ebpfdivert_user_print_fn) {
        err = ebpfdivert_user_print_fn(level, format, args);
    } else {
        err = default_print_fn(level, format, args);
    }
    va_end(args);
    return err;
}

#define pr_err(fmt, ...)  pr_log(EBPFDIVERT_ERROR, fmt, ##__VA_ARGS__)
#define pr_warn(fmt, ...) pr_log(EBPFDIVERT_WARN, fmt, ##__VA_ARGS__)
#define pr_info(fmt, ...) pr_log(EBPFDIVERT_INFO, fmt, ##__VA_ARGS__)

static int ebpfdivert_libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args) {
    char buf[512];
    va_list args_copy;
    va_copy(args_copy, args);
    vsnprintf(buf, sizeof(buf), format, args_copy);
    va_end(args_copy);

    // Silence expected benign warnings from libbpf during TC load/unload operations
    if (strstr(buf, "Invalid handle") != NULL || 
        strstr(buf, "Exclusivity flag on") != NULL ||
        strstr(buf, "Cannot find specified qdisc") != NULL ||
        strstr(buf, "Kernel error message") != NULL) {
        return 0;
    }
    
    enum ebpfdivert_print_level u_level = EBPFDIVERT_INFO;
    if (level == LIBBPF_WARN) {
        u_level = EBPFDIVERT_WARN;
    } else if (level == LIBBPF_DEBUG) {
        u_level = EBPFDIVERT_DEBUG;
    }
    
    if (ebpfdivert_user_print_fn) {
        return ebpfdivert_user_print_fn(u_level, format, args);
    } else {
        return default_print_fn(u_level, format, args);
    }
}

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
        .ifindex = ifindex,
        .attach_point = BPF_TC_INGRESS
    );

    bpf_tc_hook_create(&hook_ingress);

    DECLARE_LIBBPF_OPTS(bpf_tc_opts, opts_ingress,
        .prog_fd = bpf_program__fd(prog_ingress)
    );

    int err = bpf_tc_attach(&hook_ingress, &opts_ingress);
    if (err && err != -EEXIST) {
        pr_err("ERROR: attaching ingress program to ifindex %d failed: %s\n", ifindex, strerror(-err));
        bpf_tc_hook_destroy(&hook_ingress);
        return -1;
    }

    DECLARE_LIBBPF_OPTS(bpf_tc_hook, hook_egress,
        .ifindex = ifindex,
        .attach_point = BPF_TC_EGRESS
    );

    bpf_tc_hook_create(&hook_egress);

    DECLARE_LIBBPF_OPTS(bpf_tc_opts, opts_egress,
        .prog_fd = bpf_program__fd(prog_egress)
    );

    err = bpf_tc_attach(&hook_egress, &opts_egress);
    if (err && err != -EEXIST) {
        pr_err("ERROR: attaching egress program to ifindex %d failed: %s\n", ifindex, strerror(-err));
        DECLARE_LIBBPF_OPTS(bpf_tc_hook, hook_ingress_del,
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
        .ifindex = ifindex,
        .attach_point = BPF_TC_INGRESS | BPF_TC_EGRESS
    );
    // Check if a TC hook/qdisc exists on this interface first to prevent "Invalid handle" warning noise from libbpf
    if (bpf_tc_query(&hook, NULL) == -ENOENT) {
        return 0;
    }
    int err = bpf_tc_hook_destroy(&hook);
    return err;
}

int ebpfdivert_load(const char *ifname, const char *obj_path, uint32_t priority) {
    libbpf_set_print(ebpfdivert_libbpf_print_fn);
    // Forcefully detach/unload any existing hooks on the interface(s) to avoid EEXIST and out-of-sync maps!
    ebpfdivert_unload(ifname);

    int attach_all = (ifname == NULL || strcmp(ifname, "all") == 0);
    int ifindex = 0;
    if (!attach_all) {
        ifindex = if_nametoindex(ifname);
        if (ifindex == 0) {
            pr_err("ERROR: interface '%s' not found\n", ifname);
            return -1;
        }
    }

    struct bpf_object *obj = bpf_object__open_file(obj_path, NULL);
    if (!obj) {
        pr_err("ERROR: opening BPF object file '%s' failed\n", obj_path);
        return -1;
    }

    if (bpf_object__load(obj)) {
        pr_err("ERROR: loading BPF object file failed\n");
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
                pr_warn("WARNING: pinning map '%s' failed: %s\n", map_names[i], strerror(errno));
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
                pr_warn("WARNING: setting config in config_map failed: %s\n", strerror(errno));
            }
        }
    }

    struct bpf_program *prog_ingress = bpf_object__find_program_by_name(obj, "tc_divert_ingress");
    struct bpf_program *prog_egress = bpf_object__find_program_by_name(obj, "tc_divert_egress");
    if (!prog_ingress || !prog_egress) {
        pr_err("ERROR: programs not found in object file\n");
        cleanup_pinned_resources();
        bpf_object__close(obj);
        return -1;
    }

    int attached_count = 0;
    if (attach_all) {
        struct ifaddrs *ifaddr, *ifa;
        if (getifaddrs(&ifaddr) == -1) {
            pr_err("ERROR: getifaddrs failed: %s\n", strerror(errno));
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
            pr_err("ERROR: no active network interfaces found to attach to\n");
            cleanup_pinned_resources();
            bpf_object__close(obj);
            return -1;
        }
        pr_info("Successfully loaded and attached eBPFDivert to %d interfaces (Ingress & Egress)\n", attached_count);
    } else {
        if (attach_tc_hooks(ifindex, prog_ingress, prog_egress) != 0) {
            cleanup_pinned_resources();
            bpf_object__close(obj);
            return -1;
        }
        pr_info("Successfully loaded and attached eBPFDivert to '%s' (Ingress & Egress)\n", ifname);
    }

    // Always attach to loopback interface 'lo' to enable BPF-level redirect injection
    int lo_idx = if_nametoindex("lo");
    if (lo_idx > 0 && lo_idx != ifindex) {
        attach_tc_hooks(lo_idx, prog_ingress, prog_egress);
    }

    bpf_object__close(obj);
    return 0;
}

int ebpfdivert_unload(const char *ifname) {
    libbpf_set_print(ebpfdivert_libbpf_print_fn);
    int detach_all = (ifname == NULL || strcmp(ifname, "all") == 0);

    if (detach_all) {
        struct ifaddrs *ifaddr, *ifa;
        if (getifaddrs(&ifaddr) == -1) {
            pr_err("ERROR: getifaddrs failed: %s\n", strerror(errno));
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
        pr_info("Successfully unloaded and detached eBPFDivert from all interfaces\n");
    } else {
        int ifindex = if_nametoindex(ifname);
        if (ifindex == 0) {
            pr_err("ERROR: interface '%s' not found\n", ifname);
            return -1;
        }
        detach_tc_hooks(ifindex);
        // Also detach lo if it was attached
        int lo_idx = if_nametoindex("lo");
        if (lo_idx > 0 && lo_idx != ifindex) {
            detach_tc_hooks(lo_idx);
        }
        cleanup_pinned_resources();
        pr_info("Successfully unloaded and detached eBPFDivert from '%s'\n", ifname);
    }
    return 0;
}

int ebpfdivert_rules_clear(void) {
    int map_fd = bpf_obj_get("/sys/fs/bpf/ebpfdivert/filter_rules");
    int map_fd_v6 = bpf_obj_get("/sys/fs/bpf/ebpfdivert/filter_rules_ipv6");
    if (map_fd < 0 || map_fd_v6 < 0) {
        pr_err("ERROR: eBPFDivert maps not found. Is the driver loaded?\n");
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
    pr_info("Successfully cleared all filter rules\n");
    return 0;
}

int ebpfdivert_rules_list(void) {
    int map_fd = bpf_obj_get("/sys/fs/bpf/ebpfdivert/filter_rules");
    int map_fd_v6 = bpf_obj_get("/sys/fs/bpf/ebpfdivert/filter_rules_ipv6");
    if (map_fd < 0 || map_fd_v6 < 0) {
        pr_err("ERROR: eBPFDivert maps not found. Is the driver loaded?\n");
        if (map_fd >= 0) close(map_fd);
        if (map_fd_v6 >= 0) close(map_fd_v6);
        return -1;
    }

    printf("IPv4/Generic Rules:\n");
    printf("IDX | Proto | Action | Dst Port Range | Dst IP/Mask          | Advanced Match Details\n");
    printf("--------------------------------------------------------------------------------------\n");
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
                char ip_buf[32];
                char mask_buf[32];
                snprintf(ip_buf, sizeof(ip_buf), "%s", inet_ntoa(ip_addr));
                snprintf(mask_buf, sizeof(mask_buf), "%s", inet_ntoa(mask_addr));
                snprintf(ip_str, sizeof(ip_str), "%s/%s", ip_buf, mask_buf);
            }

            char details[256] = "";
            if (rule.match_mask & MATCH_SRC_IP) {
                struct in_addr ip_addr = { .s_addr = htonl(rule.src_ip) };
                struct in_addr mask_addr = { .s_addr = htonl(rule.src_mask) };
                char ip_buf[32];
                char mask_buf[32];
                snprintf(ip_buf, sizeof(ip_buf), "%s", inet_ntoa(ip_addr));
                snprintf(mask_buf, sizeof(mask_buf), "%s", inet_ntoa(mask_addr));
                char buf[128];
                snprintf(buf, sizeof(buf), "src_ip=%s/%s ", ip_buf, mask_buf);
                strcat(details, buf);
            }
            if (rule.match_mask & MATCH_SRC_PORT) {
                char buf[32];
                snprintf(buf, sizeof(buf), "src_port=%u-%u ", rule.src_port_start, rule.src_port_end);
                strcat(details, buf);
            }
            if (rule.match_mask & MATCH_DIRECTION) {
                strcat(details, rule.direction == 1 ? "dir=ingress " : "dir=egress ");
            }
            if (rule.match_mask & MATCH_LOOPBACK) {
                strcat(details, rule.loopback ? "loopback=yes " : "loopback=no ");
            }
            if (rule.match_mask & MATCH_TTL) {
                char buf[32];
                snprintf(buf, sizeof(buf), "ttl=%u ", rule.ttl);
                strcat(details, buf);
            }
            if (rule.match_mask & MATCH_TCP_FLAGS) {
                char buf[64];
                snprintf(buf, sizeof(buf), "tcp_flags=0x%02x/0x%02x ", rule.tcp_flags, rule.tcp_flags_mask);
                strcat(details, buf);
            }
            if (rule.invert_mask) {
                char buf[64];
                snprintf(buf, sizeof(buf), "invert=0x%04x ", rule.invert_mask);
                strcat(details, buf);
            }

            printf("%-3u | %-5s | %-6s | %-14s | %-20s | %s\n", i, proto_str, action_str, port_str, ip_str, details);
        }
    }

    printf("\nIPv6-specific Rules:\n");
    printf("IDX | Proto | Action | Dst Port Range | Dst IP/Mask          | Advanced Match Details\n");
    printf("--------------------------------------------------------------------------------------\n");
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

            char details[256] = "";
            if (rule.match_mask & MATCH_SRC_IP) {
                char ip_addr_str[64];
                char mask_addr_str[64];
                inet_ntop(AF_INET6, rule.src_ip, ip_addr_str, sizeof(ip_addr_str));
                inet_ntop(AF_INET6, rule.src_mask, mask_addr_str, sizeof(mask_addr_str));
                char buf[256];
                snprintf(buf, sizeof(buf), "src_ip=%s/%s ", ip_addr_str, mask_addr_str);
                strcat(details, buf);
            }
            if (rule.match_mask & MATCH_SRC_PORT) {
                char buf[32];
                snprintf(buf, sizeof(buf), "src_port=%u-%u ", rule.src_port_start, rule.src_port_end);
                strcat(details, buf);
            }
            if (rule.match_mask & MATCH_DIRECTION) {
                strcat(details, rule.direction == 1 ? "dir=ingress " : "dir=egress ");
            }
            if (rule.match_mask & MATCH_LOOPBACK) {
                strcat(details, rule.loopback ? "loopback=yes " : "loopback=no ");
            }
            if (rule.match_mask & MATCH_TTL) {
                char buf[32];
                snprintf(buf, sizeof(buf), "ttl=%u ", rule.ttl);
                strcat(details, buf);
            }
            if (rule.match_mask & MATCH_TCP_FLAGS) {
                char buf[64];
                snprintf(buf, sizeof(buf), "tcp_flags=0x%02x/0x%02x ", rule.tcp_flags, rule.tcp_flags_mask);
                strcat(details, buf);
            }
            if (rule.invert_mask) {
                char buf[64];
                snprintf(buf, sizeof(buf), "invert=0x%04x ", rule.invert_mask);
                strcat(details, buf);
            }

            printf("%-3u | %-5s | %-6s | %-14s | %-20s | %s\n", i, proto_str, action_str, port_str, ip_str, details);
        }
    }

    close(map_fd);
    close(map_fd_v6);
    return 0;
}

static int is_option_active(const char *val) {
    return val && strcmp(val, "any") != 0 && strlen(val) > 0;
}

static uint8_t parse_tcp_flags(const char *str) {
    if (!str) return 0;
    if (str[0] == '0' && (str[1] == 'x' || str[1] == 'X')) {
        return (uint8_t)strtol(str, NULL, 16);
    }
    uint8_t flags = 0;
    char temp[64];
    snprintf(temp, sizeof(temp), "%s", str);
    char *token = strtok(temp, ", |");
    while (token) {
        if (strcasecmp(token, "FIN") == 0) flags |= 0x01;
        else if (strcasecmp(token, "SYN") == 0) flags |= 0x02;
        else if (strcasecmp(token, "RST") == 0) flags |= 0x04;
        else if (strcasecmp(token, "PSH") == 0) flags |= 0x08;
        else if (strcasecmp(token, "ACK") == 0) flags |= 0x10;
        else if (strcasecmp(token, "URG") == 0) flags |= 0x20;
        else if (strcasecmp(token, "ECE") == 0) flags |= 0x40;
        else if (strcasecmp(token, "CWR") == 0) flags |= 0x80;
        token = strtok(NULL, ", |");
    }
    return flags;
}

int ebpfdivert_rules_add_extended(int idx, const struct ebpfdivert_rule_opt *opt) {
    if (!opt) {
        pr_err("ERROR: invalid NULL opt argument\n");
        return -1;
    }

    int map_fd = bpf_obj_get("/sys/fs/bpf/ebpfdivert/filter_rules");
    int map_fd_v6 = bpf_obj_get("/sys/fs/bpf/ebpfdivert/filter_rules_ipv6");
    if (map_fd < 0 || map_fd_v6 < 0) {
        pr_err("ERROR: eBPFDivert maps not found. Is the driver loaded?\n");
        if (map_fd >= 0) close(map_fd);
        if (map_fd_v6 >= 0) close(map_fd_v6);
        return -1;
    }

    if (idx < 0 || idx >= MAX_RULES) {
        pr_err("ERROR: rule index must be between 0 and %d\n", MAX_RULES - 1);
        close(map_fd);
        close(map_fd_v6);
        return -1;
    }

    int is_ipv6 = 0;
    if ((opt->src_ip_cidr && strchr(opt->src_ip_cidr, ':')) ||
        (opt->dst_ip_cidr && strchr(opt->dst_ip_cidr, ':')) ||
        (opt->proto && strcmp(opt->proto, "icmpv6") == 0)) {
        is_ipv6 = 1;
    }

    if (!is_ipv6) {
        struct filter_rule rule = {0};
        rule.match_mask = MATCH_ENABLED;

        if (is_option_active(opt->proto)) {
            rule.match_mask |= MATCH_PROTO;
            if (strcasecmp(opt->proto, "tcp") == 0) rule.proto = 6;
            else if (strcasecmp(opt->proto, "udp") == 0) rule.proto = 17;
            else if (strcasecmp(opt->proto, "icmp") == 0) rule.proto = 1;
            else rule.proto = atoi(opt->proto);
        }

        if (opt->action) {
            if (strcmp(opt->action, "drop") == 0) rule.match_mask |= MATCH_DROP;
            else if (strcmp(opt->action, "sniff") == 0) rule.match_mask |= MATCH_SNIFF;
        }

        if (is_option_active(opt->src_ip_cidr)) {
            rule.match_mask |= MATCH_SRC_IP;
            char ip_str[64];
            snprintf(ip_str, sizeof(ip_str), "%s", opt->src_ip_cidr);
            char *slash = strchr(ip_str, '/');
            int bits = 32;
            if (slash) {
                *slash = '\0';
                bits = atoi(slash + 1);
            }
            unsigned long addr = inet_addr(ip_str);
            if (addr == INADDR_NONE) {
                pr_err("ERROR: invalid IP address '%s'\n", ip_str);
                close(map_fd);
                close(map_fd_v6);
                return -1;
            }
            if (bits < 0 || bits > 32) {
                pr_err("ERROR: invalid CIDR mask bits %d\n", bits);
                close(map_fd);
                close(map_fd_v6);
                return -1;
            }
            rule.src_ip = ntohl(addr);
            if (bits >= 32) rule.src_mask = 0xFFFFFFFF;
            else if (bits <= 0) rule.src_mask = 0;
            else rule.src_mask = (0xFFFFFFFF << (32 - bits));
        }

        if (is_option_active(opt->dst_ip_cidr)) {
            rule.match_mask |= MATCH_DST_IP;
            char ip_str[64];
            snprintf(ip_str, sizeof(ip_str), "%s", opt->dst_ip_cidr);
            char *slash = strchr(ip_str, '/');
            int bits = 32;
            if (slash) {
                *slash = '\0';
                bits = atoi(slash + 1);
            }
            unsigned long addr = inet_addr(ip_str);
            if (addr == INADDR_NONE) {
                pr_err("ERROR: invalid IP address '%s'\n", ip_str);
                close(map_fd);
                close(map_fd_v6);
                return -1;
            }
            if (bits < 0 || bits > 32) {
                pr_err("ERROR: invalid CIDR mask bits %d\n", bits);
                close(map_fd);
                close(map_fd_v6);
                return -1;
            }
            rule.dst_ip = ntohl(addr);
            if (bits >= 32) rule.dst_mask = 0xFFFFFFFF;
            else if (bits <= 0) rule.dst_mask = 0;
            else rule.dst_mask = (0xFFFFFFFF << (32 - bits));
        }

        if (is_option_active(opt->src_port_range) && rule.proto != 1) {
            rule.match_mask |= MATCH_SRC_PORT;
            char pr_str[32];
            snprintf(pr_str, sizeof(pr_str), "%s", opt->src_port_range);
            char *dash = strchr(pr_str, '-');
            if (dash) {
                *dash = '\0';
                rule.src_port_start = atoi(pr_str);
                rule.src_port_end = atoi(dash + 1);
            } else {
                int p = atoi(pr_str);
                rule.src_port_start = p;
                rule.src_port_end = p;
            }
        }

        if (is_option_active(opt->dst_port_range)) {
            rule.match_mask |= MATCH_DST_PORT;
            if (rule.proto == 1) {
                char pr_str[32];
                snprintf(pr_str, sizeof(pr_str), "%s", opt->dst_port_range);
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
                snprintf(pr_str, sizeof(pr_str), "%s", opt->dst_port_range);
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

        if (is_option_active(opt->direction)) {
            rule.match_mask |= MATCH_DIRECTION;
            if (strcasecmp(opt->direction, "ingress") == 0) rule.direction = 1;
            else if (strcasecmp(opt->direction, "egress") == 0) rule.direction = 2;
        }

        if (is_option_active(opt->loopback)) {
            rule.match_mask |= MATCH_LOOPBACK;
            if (strcasecmp(opt->loopback, "yes") == 0) rule.loopback = 1;
            else if (strcasecmp(opt->loopback, "no") == 0) rule.loopback = 0;
        }

        if (is_option_active(opt->ttl)) {
            rule.match_mask |= MATCH_TTL;
            rule.ttl = (uint8_t)atoi(opt->ttl);
        }

        if (is_option_active(opt->tcp_flags)) {
            rule.match_mask |= MATCH_TCP_FLAGS;
            rule.tcp_flags = parse_tcp_flags(opt->tcp_flags);
            if (is_option_active(opt->tcp_flags_mask)) {
                rule.tcp_flags_mask = parse_tcp_flags(opt->tcp_flags_mask);
            } else {
                rule.tcp_flags_mask = 0xFF;
            }
        }

        rule.invert_mask = opt->invert_mask;

        if (bpf_map_update_elem(map_fd, &idx, &rule, BPF_ANY)) {
            pr_err("ERROR: updating filter_rules map failed: %s\n", strerror(errno));
            close(map_fd);
            close(map_fd_v6);
            return -1;
        }
    } else {
        struct filter_rule_ipv6 rule = {0};
        rule.match_mask = MATCH_ENABLED;

        if (is_option_active(opt->proto)) {
            rule.match_mask |= MATCH_PROTO;
            if (strcasecmp(opt->proto, "tcp") == 0) rule.proto = 6;
            else if (strcasecmp(opt->proto, "udp") == 0) rule.proto = 17;
            else if (strcasecmp(opt->proto, "icmpv6") == 0) rule.proto = 58;
            else rule.proto = atoi(opt->proto);
        }

        if (opt->action) {
            if (strcmp(opt->action, "drop") == 0) rule.match_mask |= MATCH_DROP;
            else if (strcmp(opt->action, "sniff") == 0) rule.match_mask |= MATCH_SNIFF;
        }

        if (is_option_active(opt->src_ip_cidr)) {
            rule.match_mask |= MATCH_SRC_IP;
            char ip_str[128];
            snprintf(ip_str, sizeof(ip_str), "%s", opt->src_ip_cidr);
            char *slash = strchr(ip_str, '/');
            int bits = 128;
            if (slash) {
                *slash = '\0';
                bits = atoi(slash + 1);
            }
            if (inet_pton(AF_INET6, ip_str, rule.src_ip) != 1) {
                pr_err("ERROR: invalid IPv6 address '%s'\n", ip_str);
                close(map_fd);
                close(map_fd_v6);
                return -1;
            }
            if (bits < 0 || bits > 128) {
                pr_err("ERROR: invalid IPv6 CIDR mask bits %d\n", bits);
                close(map_fd);
                close(map_fd_v6);
                return -1;
            }
            for (int i = 0; i < 16; i++) {
                if (bits >= 8) {
                    rule.src_mask[i] = 0xFF;
                    bits -= 8;
                } else if (bits > 0) {
                    rule.src_mask[i] = (0xFF << (8 - bits));
                    bits = 0;
                } else {
                    rule.src_mask[i] = 0;
                }
            }
        }

        if (is_option_active(opt->dst_ip_cidr)) {
            rule.match_mask |= MATCH_DST_IP;
            char ip_str[128];
            snprintf(ip_str, sizeof(ip_str), "%s", opt->dst_ip_cidr);
            char *slash = strchr(ip_str, '/');
            int bits = 128;
            if (slash) {
                *slash = '\0';
                bits = atoi(slash + 1);
            }
            if (inet_pton(AF_INET6, ip_str, rule.dst_ip) != 1) {
                pr_err("ERROR: invalid IPv6 address '%s'\n", ip_str);
                close(map_fd);
                close(map_fd_v6);
                return -1;
            }
            if (bits < 0 || bits > 128) {
                pr_err("ERROR: invalid IPv6 CIDR mask bits %d\n", bits);
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

        if (is_option_active(opt->src_port_range) && rule.proto != 58) {
            rule.match_mask |= MATCH_SRC_PORT;
            char pr_str[32];
            snprintf(pr_str, sizeof(pr_str), "%s", opt->src_port_range);
            char *dash = strchr(pr_str, '-');
            if (dash) {
                *dash = '\0';
                rule.src_port_start = atoi(pr_str);
                rule.src_port_end = atoi(dash + 1);
            } else {
                int p = atoi(pr_str);
                rule.src_port_start = p;
                rule.src_port_end = p;
            }
        }

        if (is_option_active(opt->dst_port_range)) {
            rule.match_mask |= MATCH_DST_PORT;
            if (rule.proto == 58) {
                char pr_str[32];
                snprintf(pr_str, sizeof(pr_str), "%s", opt->dst_port_range);
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
                snprintf(pr_str, sizeof(pr_str), "%s", opt->dst_port_range);
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

        if (is_option_active(opt->direction)) {
            rule.match_mask |= MATCH_DIRECTION;
            if (strcasecmp(opt->direction, "ingress") == 0) rule.direction = 1;
            else if (strcasecmp(opt->direction, "egress") == 0) rule.direction = 2;
        }

        if (is_option_active(opt->loopback)) {
            rule.match_mask |= MATCH_LOOPBACK;
            if (strcasecmp(opt->loopback, "yes") == 0) rule.loopback = 1;
            else if (strcasecmp(opt->loopback, "no") == 0) rule.loopback = 0;
        }

        if (is_option_active(opt->ttl)) {
            rule.match_mask |= MATCH_TTL;
            rule.ttl = (uint8_t)atoi(opt->ttl);
        }

        if (is_option_active(opt->tcp_flags)) {
            rule.match_mask |= MATCH_TCP_FLAGS;
            rule.tcp_flags = parse_tcp_flags(opt->tcp_flags);
            if (is_option_active(opt->tcp_flags_mask)) {
                rule.tcp_flags_mask = parse_tcp_flags(opt->tcp_flags_mask);
            } else {
                rule.tcp_flags_mask = 0xFF;
            }
        }

        rule.invert_mask = opt->invert_mask;

        if (bpf_map_update_elem(map_fd_v6, &idx, &rule, BPF_ANY)) {
            pr_err("ERROR: updating filter_rules_ipv6 map failed: %s\n", strerror(errno));
            close(map_fd);
            close(map_fd_v6);
            return -1;
        }
    }

    close(map_fd);
    close(map_fd_v6);
    pr_info("Successfully added rule at index %d\n", idx);
    return 0;
}

int ebpfdivert_rules_add(int idx, const char *proto, const char *ip_cidr, const char *port_range, const char *action) {
    if (!proto || !ip_cidr || !port_range || !action) {
        pr_err("ERROR: invalid NULL argument to ebpfdivert_rules_add\n");
        return -1;
    }

    int map_fd = bpf_obj_get("/sys/fs/bpf/ebpfdivert/filter_rules");
    int map_fd_v6 = bpf_obj_get("/sys/fs/bpf/ebpfdivert/filter_rules_ipv6");
    if (map_fd < 0 || map_fd_v6 < 0) {
        pr_err("ERROR: eBPFDivert maps not found. Is the driver loaded?\n");
        if (map_fd >= 0) close(map_fd);
        if (map_fd_v6 >= 0) close(map_fd_v6);
        return -1;
    }

    if (idx < 0 || idx >= MAX_RULES) {
        pr_err("ERROR: rule index must be between 0 and %d\n", MAX_RULES - 1);
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
            snprintf(ip_str, sizeof(ip_str), "%s", ip_cidr);
            char *slash = strchr(ip_str, '/');
            int bits = 32;
            if (slash) {
                *slash = '\0';
                bits = atoi(slash + 1);
            }
            unsigned long addr = inet_addr(ip_str);
            if (addr == INADDR_NONE) {
                pr_err("ERROR: invalid IP address '%s'\n", ip_str);
                close(map_fd);
                close(map_fd_v6);
                return -1;
            }
            if (bits < 0 || bits > 32) {
                pr_err("ERROR: invalid CIDR mask bits %d\n", bits);
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
                snprintf(pr_str, sizeof(pr_str), "%s", port_range);
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
                snprintf(pr_str, sizeof(pr_str), "%s", port_range);
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
            pr_err("ERROR: updating filter_rules map failed: %s\n", strerror(errno));
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
            snprintf(ip_str, sizeof(ip_str), "%s", ip_cidr);
            char *slash = strchr(ip_str, '/');
            int bits = 128;
            if (slash) {
                *slash = '\0';
                bits = atoi(slash + 1);
            }
            if (inet_pton(AF_INET6, ip_str, rule.dst_ip) != 1) {
                pr_err("ERROR: invalid IPv6 address '%s'\n", ip_str);
                close(map_fd);
                close(map_fd_v6);
                return -1;
            }
            if (bits < 0 || bits > 128) {
                pr_err("ERROR: invalid IPv6 CIDR mask bits %d\n", bits);
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
                snprintf(pr_str, sizeof(pr_str), "%s", port_range);
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
                snprintf(pr_str, sizeof(pr_str), "%s", port_range);
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
            pr_err("ERROR: updating filter_rules_ipv6 map failed: %s\n", strerror(errno));
            close(map_fd);
            close(map_fd_v6);
            return -1;
        }
    }

    close(map_fd);
    close(map_fd_v6);
    pr_info("Successfully added rule at index %d\n", idx);
    return 0;
}

int ebpfdivert_get_stats(uint64_t *stats, int stats_len) {
    int stats_fd = bpf_obj_get("/sys/fs/bpf/ebpfdivert/stats_map");
    if (stats_fd < 0) {
        return -1;
    }

    int num_cpus = libbpf_num_possible_cpus();
    if (num_cpus <= 0) {
        close(stats_fd);
        return -1;
    }
    __u64 values[num_cpus];

    for (__u32 key = 0; key < (__u32)stats_len; key++) {
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

struct pkt_queue_entry {
    struct divert_packet_buffer pkt;
    size_t size;
    struct pkt_queue_entry *next;
};

struct if_sock_entry {
    int ifindex;        // The interface bound to (lo or target)
    int target_ifindex; // Destination target interface
    int is_redirect;    // Flag indicating this is a redirect injection socket
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

    struct pkt_queue_entry *queue_head;
    struct pkt_queue_entry *queue_tail;
    int queue_size;
    int max_queue_size;

    // Cache of interface-specific raw sockets for TX ring injection
    struct if_sock_entry *socks;
    int socks_count;
    int socks_capacity;
};

static int ebpfdivert_rb_callback(void *ctx, void *data, size_t size) {
    struct ebpfdivert_handle *h = ctx;
    if (!h) return 0;
    
    if (!h->curr_received) {
        size_t to_copy = (size < h->curr_buf_len) ? size : h->curr_buf_len;
        memcpy(h->curr_buf, data, to_copy);
        h->curr_received = 1;
    } else {
        if (h->queue_size >= h->max_queue_size) {
            int stats_fd = bpf_obj_get("/sys/fs/bpf/ebpfdivert/stats_map");
            if (stats_fd >= 0) {
                __u32 key = STAT_QUEUE_FULL;
                int num_cpus = libbpf_num_possible_cpus();
                __u64 values[num_cpus];
                memset(values, 0, sizeof(values));
                if (bpf_map_lookup_elem(stats_fd, &key, values) == 0) {
                    values[0] += 1;
                    bpf_map_update_elem(stats_fd, &key, values, BPF_ANY);
                }
                close(stats_fd);
            }
            return 0; // Drop packet (backpressure)
        }
        struct pkt_queue_entry *entry = malloc(sizeof(struct pkt_queue_entry));
        if (entry) {
            size_t to_copy = (size < sizeof(struct divert_packet_buffer)) ? size : sizeof(struct divert_packet_buffer);
            memcpy(&entry->pkt, data, to_copy);
            entry->size = size;
            entry->next = NULL;
            if (h->queue_tail) {
                h->queue_tail->next = entry;
                h->queue_tail = entry;
            } else {
                h->queue_head = entry;
                h->queue_tail = entry;
            }
            h->queue_size++;
        }
    }
    return 0;
}

ebpfdivert_handle_t *ebpfdivert_open(uint32_t priority) {
    struct ebpfdivert_handle *h = calloc(1, sizeof(struct ebpfdivert_handle));
    if (!h) return NULL;
    
    h->priority = priority;
    h->ringbuf_fd = -1;
    h->queue_head = NULL;
    h->queue_tail = NULL;
    h->queue_size = 0;
    h->max_queue_size = 1024; // Default max queue size
    
    h->ringbuf_fd = bpf_obj_get("/sys/fs/bpf/ebpfdivert/pcap_ringbuf");
    if (h->ringbuf_fd < 0) {
        pr_err("ERROR: pcap_ringbuf map not found. Is the driver loaded?\n");
        free(h);
        return NULL;
    }
    
    h->rb = ring_buffer__new(h->ringbuf_fd, ebpfdivert_rb_callback, h, NULL);
    if (!h->rb) {
        pr_err("ERROR: failed to create ring buffer consumer\n");
        close(h->ringbuf_fd);
        free(h);
        return NULL;
    }
    
    h->socks_capacity = 16;
    h->socks = calloc(h->socks_capacity, sizeof(struct if_sock_entry));
    if (!h->socks) {
        pr_err("ERROR: failed to allocate raw sockets cache\n");
        ring_buffer__free(h->rb);
        close(h->ringbuf_fd);
        free(h);
        return NULL;
    }
    h->socks_count = 0;
    return h;
}

int ebpfdivert_recv(ebpfdivert_handle_t *h, struct divert_packet_buffer *buf, size_t buf_len, int timeout_ms) {
    if (!h || !buf) return -EINVAL;
    
    if (h->queue_head) {
        struct pkt_queue_entry *entry = h->queue_head;
        size_t to_copy = (entry->size < buf_len) ? entry->size : buf_len;
        memcpy(buf, &entry->pkt, to_copy);
        h->queue_head = entry->next;
        if (!h->queue_head) {
            h->queue_tail = NULL;
        }
        h->queue_size--;
        free(entry);
        return 0;
    }
    
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
    
    size_t to_send = buf->header.cap_len;
    if (to_send > buf->header.pkt_len) {
        to_send = buf->header.pkt_len;
    }
    if (to_send > 2048) {
        to_send = 2048;
    }
    
    int is_redirect = (buf->header.direction == 1);
    int target_ifindex = ifindex;
    int lo_idx = if_nametoindex("lo");
    if (lo_idx <= 0) lo_idx = 1;
    
    int bind_ifindex = is_redirect ? lo_idx : target_ifindex;
    if (target_ifindex == lo_idx) {
        is_redirect = 1;
        bind_ifindex = lo_idx;
    }
    
    int sock_idx = -1;
    for (int i = 0; i < h->socks_count; i++) {
        if (h->socks[i].is_redirect == is_redirect && 
            h->socks[i].target_ifindex == target_ifindex) {
            sock_idx = i;
            break;
        }
    }
    
    if (sock_idx == -1) {
        if (h->socks_count >= h->socks_capacity) {
            int new_capacity = h->socks_capacity * 2;
            struct if_sock_entry *new_socks = realloc(h->socks, new_capacity * sizeof(struct if_sock_entry));
            if (!new_socks) {
                return -ENOMEM;
            }
            h->socks = new_socks;
            memset(&h->socks[h->socks_capacity], 0, (new_capacity - h->socks_capacity) * sizeof(struct if_sock_entry));
            h->socks_capacity = new_capacity;
        }
        int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
        if (sock < 0) {
            return -errno;
        }
        
        uint32_t mark;
        if (is_redirect) {
            mark = REDIRECT_MARK_MASK | (target_ifindex & 0xFFFF);
        } else {
            mark = 0x4D490000 | (h->priority & 0xFFFF);
        }
        
        if (setsockopt(sock, SOL_SOCKET, SO_MARK, &mark, sizeof(mark)) < 0) {
            close(sock);
            return -errno;
        }
        
        struct sockaddr_ll sll;
        memset(&sll, 0, sizeof(sll));
        sll.sll_family = AF_PACKET;
        sll.sll_ifindex = bind_ifindex;
        sll.sll_protocol = htons(ETH_P_ALL);
        if (bind(sock, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
            close(sock);
            return -errno;
        }
        
        sock_idx = h->socks_count;
        h->socks[sock_idx].ifindex = bind_ifindex;
        h->socks[sock_idx].target_ifindex = target_ifindex;
        h->socks[sock_idx].is_redirect = is_redirect;
        h->socks[sock_idx].sock = sock;
        h->socks[sock_idx].tx_ring = NULL;
        h->socks[sock_idx].tx_index = 0;
        h->socks_count++;
    }
    
    int sock = h->socks[sock_idx].sock;
    ssize_t sent = send(sock, buf->data, to_send, 0);
    if (sent < 0) {
        return -errno;
    }
    
    return 0;
}

int ebpfdivert_set_max_queue_size(ebpfdivert_handle_t *h, int size) {
    if (!h || size <= 0) return -EINVAL;
    h->max_queue_size = size;
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
    free(h->socks);
    
    // Free the packet queue
    struct pkt_queue_entry *curr = h->queue_head;
    while (curr) {
        struct pkt_queue_entry *next = curr->next;
        free(curr);
        curr = next;
    }
    
    if (h->rb) {
        ring_buffer__free(h->rb);
    }
    if (h->ringbuf_fd >= 0) {
        close(h->ringbuf_fd);
    }
    free(h);
}
