// SPDX-License-Identifier: GPL-2.0-or-later OR LGPL-3.0-or-later
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include "ebpfdivert.h"

void print_usage(const char *prog_name) {
    printf("Usage: %s <command> [args]\n", prog_name);
    printf("Commands:\n");
    printf("  sniff [filter] [pcap_file]          Sniff packets matching a WinDivert filter (Ctrl+C to stop)\n");
    printf("  cleanup                             Detach programs left behind by crashed processes\n");
    printf("\nPinned global mode:\n");
    printf("  load [interface] [priority] [bpf_object_path]  Attach driver (defaults to 'all' interfaces, priority 0,\n");
    printf("                                      embedded BPF object)\n");
    printf("  unload [interface]                  Detach driver (defaults to 'all' interfaces)\n");
    printf("  stats                               Print packet telemetry stats\n");
    printf("  rules list                          List all active rules\n");
    printf("  rules clear                         Clear all active rules\n");
    printf("  rules add <idx> <proto> <dst_ip/mask> <dst_port_range> <action>\n");
    printf("                                      Add a new rule (idx 0-%d)\n", MAX_RULES - 1);
    printf("                                      proto: tcp, udp, icmp, icmpv6, any\n");
    printf("                                      dst_ip/mask: e.g. 192.168.1.0/24, any\n");
    printf("                                      dst_port_range: e.g. 80, 8000-8010, type/code for icmp, any\n");
    printf("                                      action: divert, drop, sniff\n");
    printf("  rules add-ext <idx> <action> [opts] Add advanced rule with source matching, loopback, direction, TCP flags, TTL, and inversion options\n");
    printf("  version                             Print version information\n");
}

int cli_stats() {
    uint64_t stats[STAT_MAX] = {0};
    if (ebpfdivert_get_stats(stats, STAT_MAX)) {
        fprintf(stderr, "ERROR: eBPFDivert stats map not found. Is the driver loaded?\n");
        return -1;
    }

    const char *stat_names[] = {
        "Diverted",
        "Dropped",
        "Sniffed",
        "Parsing Errors",
        "Ringbuf Full",
        "Queue Full",
        "Too Big",
        "Owner Gone"
    };

    printf("eBPFDivert Statistics:\n");
    printf("Metric          | Value\n");
    printf("---------------------------\n");
    for (int i = 0; i < STAT_MAX; i++) {
        printf("%-15s | %lu\n", stat_names[i], stats[i]);
    }
    return 0;
}

#include <signal.h>
#include <time.h>

struct pcap_hdr {
    uint32_t magic_number;
    uint16_t version_major;
    uint16_t version_minor;
    int32_t  thiszone;
    uint32_t sigfigs;
    uint32_t snaplen;
    uint32_t network;
};

struct pcaprec_hdr {
    uint32_t ts_sec;
    uint32_t ts_usec;
    uint32_t incl_len;
    uint32_t orig_len;
};

static void write_pcap_header(FILE *f) {
    struct pcap_hdr hdr = {
        .magic_number = 0xa1b2c3d4,
        .version_major = 2,
        .version_minor = 4,
        .thiszone = 0,
        .sigfigs = 0,
        .snaplen = 65535,
        .network = 101 // LINKTYPE_RAW: packets start at the IP header
    };
    fwrite(&hdr, sizeof(hdr), 1, f);
}

static void write_pcap_packet(FILE *f, const uint8_t *pkt, uint32_t len) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    struct pcaprec_hdr phdr = {
        .ts_sec = (uint32_t)ts.tv_sec,
        .ts_usec = (uint32_t)(ts.tv_nsec / 1000),
        .incl_len = len,
        .orig_len = len
    };
    fwrite(&phdr, sizeof(phdr), 1, f);
    fwrite(pkt, len, 1, f);
}

static volatile sig_atomic_t stop_sniffing;

static void on_signal(int sig) {
    (void)sig;
    stop_sniffing = 1;
}

int cli_sniff(const char *filter, const char *pcap_filename) {
    ebpfdivert_handle_t *h = ebpfdivert_open(filter, EBPFDIVERT_LAYER_NETWORK, 0,
                                             EBPFDIVERT_FLAG_SNIFF | EBPFDIVERT_FLAG_RECV_ONLY, NULL);
    if (!h) {
        int err = errno;
        const char *err_str = NULL;
        uint32_t err_pos = 0;
        if (err == EINVAL &&
            ebpfdivert_helper_compile_filter(filter, EBPFDIVERT_LAYER_NETWORK, &err_str, &err_pos) != 0) {
            fprintf(stderr, "ERROR: invalid filter at position %u: %s\n", err_pos, err_str);
        } else {
            fprintf(stderr, "ERROR: failed to open eBPFDivert handle: %s\n", strerror(err));
        }
        return -1;
    }

    FILE *pcap_file = NULL;
    if (pcap_filename) {
        pcap_file = fopen(pcap_filename, "wb");
        if (!pcap_file) {
            fprintf(stderr, "ERROR: failed to open PCAP file '%s' for writing: %s\n", pcap_filename, strerror(errno));
            ebpfdivert_close(h);
            return -1;
        }
        write_pcap_header(pcap_file);
        printf("Sniffing '%s' to '%s'...\n", filter, pcap_filename);
    } else {
        printf("Sniffing '%s' to console...\n", filter);
    }

    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);

    static uint8_t pkt[EBPFDIVERT_MTU_MAX];
    struct ebpfdivert_address addr;
    uint32_t len;
    int ret = 0;
    while (!stop_sniffing) {
        int r = ebpfdivert_recv(h, pkt, sizeof(pkt), &len, &addr, 200);
        if (r == -EAGAIN || r == -EINTR) {
            continue;
        } else if (r < 0) {
            fprintf(stderr, "ERROR: receiving packet failed: %s\n", ebpfdivert_strerror(r));
            ret = -1;
            break;
        }

        const char *proto_str = "UNKNOWN";
        uint8_t proto = 0;
        if (len >= 20) {
            proto = addr.ipv6 ? pkt[6] : pkt[9];
        }
        if (proto == 6) proto_str = "TCP";
        else if (proto == 17) proto_str = "UDP";
        else if (proto == 1) proto_str = "ICMP";
        else if (proto == 58) proto_str = "ICMPv6";

        printf("[%8s%s] IfIndex: %u, Len: %u, Proto: %s (%u)\n",
               addr.outbound ? "OUTBOUND" : "INBOUND", addr.loopback ? ",LO" : "",
               addr.network.if_idx, len, proto_str, proto);

        if (pcap_file) {
            write_pcap_packet(pcap_file, pkt, len);
            fflush(pcap_file);
        }
    }

    if (pcap_file) {
        fclose(pcap_file);
    }
    ebpfdivert_close(h);
    return ret;
}

int cli_print_fn(enum ebpfdivert_print_level level, const char *format, va_list args) {
    if (level > EBPFDIVERT_INFO) {
        return 0;
    }
    if (level <= EBPFDIVERT_WARN) {
        return vfprintf(stderr, format, args);
    } else {
        return vfprintf(stdout, format, args);
    }
}

int main(int argc, char **argv) {
    ebpfdivert_set_print(cli_print_fn);
    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }

    const char *cmd = argv[1];

    if (strcmp(cmd, "version") == 0 || strcmp(cmd, "--version") == 0 || strcmp(cmd, "-v") == 0) {
        printf("ebpfdivert-cli version %s (libebpfdivert %s)\n", EBPFDIVERT_VERSION, ebpfdivert_version());
        return 0;
    }

    if (strcmp(cmd, "load") == 0) {
        const char *ifname = NULL;
        uint32_t priority = 0;
        const char *obj_path = NULL;

        if (argc >= 3) {
            const char *arg = argv[2];
            char *endptr;
            long p_val = strtol(arg, &endptr, 10);
            if (*endptr == '\0' && p_val >= 0) {
                priority = (uint32_t)p_val;
                if (argc >= 4) {
                    obj_path = argv[3];
                }
            } else if (strstr(arg, ".o") != NULL) {
                obj_path = arg;
                if (argc >= 4) {
                    priority = (uint32_t)atoi(argv[3]);
                }
            } else {
                ifname = arg;
                if (argc >= 4) {
                    long p_val2 = strtol(argv[3], &endptr, 10);
                    if (*endptr == '\0' && p_val2 >= 0) {
                        priority = (uint32_t)p_val2;
                        if (argc >= 5) {
                            obj_path = argv[4];
                        }
                    } else {
                        obj_path = argv[3];
                        if (argc >= 5) {
                            priority = (uint32_t)atoi(argv[4]);
                        }
                    }
                }
            }
        }
        return ebpfdivert_load(ifname, obj_path, priority) ? 1 : 0;
    } else if (strcmp(cmd, "unload") == 0) {
        const char *ifname = NULL;
        if (argc >= 3) {
            ifname = argv[2];
        }
        return ebpfdivert_unload(ifname) ? 1 : 0;
    } else if (strcmp(cmd, "stats") == 0) {
        return cli_stats() ? 1 : 0;
    } else if (strcmp(cmd, "sniff") == 0) {
        const char *filter = (argc >= 3) ? argv[2] : "true";
        const char *pcap_filename = (argc >= 4) ? argv[3] : NULL;
        return cli_sniff(filter, pcap_filename) ? 1 : 0;
    } else if (strcmp(cmd, "cleanup") == 0) {
        return ebpfdivert_unregister() ? 1 : 0;
    } else if (strcmp(cmd, "rules") == 0) {
        if (argc < 3) {
            fprintf(stderr, "Usage: %s rules <list|clear|add|add-ext> [args]\n", argv[0]);
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
        } else if (strcmp(subcmd, "add-ext") == 0) {
            if (argc < 5) {
                fprintf(stderr, "Usage: %s rules add-ext <idx> <action> [options...]\n", argv[0]);
                fprintf(stderr, "Options:\n");
                fprintf(stderr, "  --proto <proto>           tcp, udp, icmp, icmpv6, any\n");
                fprintf(stderr, "  --src-ip <ip/mask>        Source IP and CIDR mask\n");
                fprintf(stderr, "  --dst-ip <ip/mask>        Destination IP and CIDR mask\n");
                fprintf(stderr, "  --src-port <port_range>   Source port range (e.g. 80, 80-90)\n");
                fprintf(stderr, "  --dst-port <port_range>   Destination port range (e.g. 80, 80-90, or type/code)\n");
                fprintf(stderr, "  --direction <dir>         ingress, egress, any\n");
                fprintf(stderr, "  --loopback <lo>           yes, no, any\n");
                fprintf(stderr, "  --ttl <ttl>               Time to Live (0-255)\n");
                fprintf(stderr, "  --tcp-flags <flags>       e.g. SYN, ACK, RST, or 0x02\n");
                fprintf(stderr, "  --tcp-flags-mask <mask>  TCP flags verification mask\n");
                fprintf(stderr, "  --invert <fields>         Comma-separated fields to invert (src-ip, dst-ip, src-port, dst-port, proto, direction, loopback, ttl)\n");
                return 1;
            }
            int idx = atoi(argv[3]);
            const char *action = argv[4];
            
            struct ebpfdivert_rule_opt opt = {0};
            opt.action = action;
            opt.proto = "any";
            opt.src_ip_cidr = "any";
            opt.dst_ip_cidr = "any";
            opt.src_port_range = "any";
            opt.dst_port_range = "any";
            opt.direction = "any";
            opt.loopback = "any";
            opt.ttl = "any";
            opt.tcp_flags = "any";
            opt.tcp_flags_mask = "any";
            opt.invert_mask = 0;
            
            for (int i = 5; i < argc; i++) {
                if (strcmp(argv[i], "--proto") == 0 && i + 1 < argc) {
                    opt.proto = argv[++i];
                } else if (strcmp(argv[i], "--src-ip") == 0 && i + 1 < argc) {
                    opt.src_ip_cidr = argv[++i];
                } else if (strcmp(argv[i], "--dst-ip") == 0 && i + 1 < argc) {
                    opt.dst_ip_cidr = argv[++i];
                } else if (strcmp(argv[i], "--src-port") == 0 && i + 1 < argc) {
                    opt.src_port_range = argv[++i];
                } else if (strcmp(argv[i], "--dst-port") == 0 && i + 1 < argc) {
                    opt.dst_port_range = argv[++i];
                } else if (strcmp(argv[i], "--direction") == 0 && i + 1 < argc) {
                    opt.direction = argv[++i];
                } else if (strcmp(argv[i], "--loopback") == 0 && i + 1 < argc) {
                    opt.loopback = argv[++i];
                } else if (strcmp(argv[i], "--ttl") == 0 && i + 1 < argc) {
                    opt.ttl = argv[++i];
                } else if (strcmp(argv[i], "--tcp-flags") == 0 && i + 1 < argc) {
                    opt.tcp_flags = argv[++i];
                } else if (strcmp(argv[i], "--tcp-flags-mask") == 0 && i + 1 < argc) {
                    opt.tcp_flags_mask = argv[++i];
                } else if (strcmp(argv[i], "--invert") == 0 && i + 1 < argc) {
                    char temp[256];
                    snprintf(temp, sizeof(temp), "%s", argv[++i]);
                    char *tok = strtok(temp, ",");
                    while (tok) {
                        if (strcasecmp(tok, "src-ip") == 0) opt.invert_mask |= MATCH_SRC_IP;
                        else if (strcasecmp(tok, "dst-ip") == 0) opt.invert_mask |= MATCH_DST_IP;
                        else if (strcasecmp(tok, "src-port") == 0) opt.invert_mask |= MATCH_SRC_PORT;
                        else if (strcasecmp(tok, "dst-port") == 0) opt.invert_mask |= MATCH_DST_PORT;
                        else if (strcasecmp(tok, "proto") == 0) opt.invert_mask |= MATCH_PROTO;
                        else if (strcasecmp(tok, "direction") == 0) opt.invert_mask |= MATCH_DIRECTION;
                        else if (strcasecmp(tok, "loopback") == 0) opt.invert_mask |= MATCH_LOOPBACK;
                        else if (strcasecmp(tok, "ttl") == 0) opt.invert_mask |= MATCH_TTL;
                        tok = strtok(NULL, ",");
                    }
                }
            }
            return ebpfdivert_rules_add_extended(idx, &opt) ? 1 : 0;
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
