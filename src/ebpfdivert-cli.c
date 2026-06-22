// SPDX-License-Identifier: GPL-2.0-or-later OR LGPL-3.0-or-later
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "ebpfdivert.h"

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

int cli_stats() {
    uint64_t stats[5] = {0};
    if (ebpfdivert_get_stats(stats, 5)) {
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
    for (int i = 0; i < 5; i++) {
        printf("%-15s | %lu\n", stat_names[i], stats[i]);
    }
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
        return ebpfdivert_load(ifname, obj_path) ? 1 : 0;
    } else if (strcmp(cmd, "unload") == 0) {
        if (argc < 3) {
            fprintf(stderr, "Usage: %s unload <interface>\n", argv[0]);
            return 1;
        }
        const char *ifname = argv[2];
        return ebpfdivert_unload(ifname) ? 1 : 0;
    } else if (strcmp(cmd, "stats") == 0) {
        return cli_stats() ? 1 : 0;
    } else if (strcmp(cmd, "rules") == 0) {
        if (argc < 3) {
            fprintf(stderr, "Usage: %s rules <list|clear|add> [args]\n", argv[0]);
            return 1;
        }
        const char *subcmd = argv[2];
        if (strcmp(subcmd, "list") == 0) {
            return ebpfdivert_rules_list() ? 1 : 0;
        } else if (strcmp(subcmd, "clear") == 0) {
            return ebpfdivert_rules_clear() ? 1 : 0;
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
            return ebpfdivert_rules_add(idx, proto, ip_cidr, port_range, action) ? 1 : 0;
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
