// SPDX-License-Identifier: GPL-2.0-or-later OR LGPL-3.0-or-later
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include "ebpfdivert.h"

void print_usage(const char *prog_name) {
    printf("Usage: %s <command> [args]\n", prog_name);
    printf("Commands:\n");
    printf("  load [interface] [priority] [bpf_object_path]  Attach driver (defaults to 'all' interfaces, priority 0)\n");
    printf("  unload [interface]                  Detach driver (defaults to 'all' interfaces)\n");
    printf("  stats                               Print packet telemetry stats\n");
    printf("  sniff [pcap_file]                   Sniff captured packets (Ctrl+C to stop)\n");
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

#include <sys/time.h>

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
        .network = 1 // Ethernet
    };
    fwrite(&hdr, sizeof(hdr), 1, f);
}

static void write_pcap_packet(FILE *f, const struct divert_packet_buffer *buf) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    
    struct pcaprec_hdr phdr = {
        .ts_sec = (uint32_t)tv.tv_sec,
        .ts_usec = (uint32_t)tv.tv_usec,
        .incl_len = buf->header.pkt_len > 2048 ? 2048 : buf->header.pkt_len,
        .orig_len = buf->header.pkt_len
    };
    fwrite(&phdr, sizeof(phdr), 1, f);
    fwrite(buf->data, phdr.incl_len, 1, f);
}

int cli_sniff(const char *pcap_filename) {
    ebpfdivert_handle_t *h = ebpfdivert_open(0);
    if (!h) {
        fprintf(stderr, "ERROR: failed to open eBPFDivert handle. Is the driver loaded?\n");
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
        printf("Sniffing packets to '%s'...\n", pcap_filename);
    } else {
        printf("Sniffing packets to console...\n");
    }
    
    struct divert_packet_buffer buf;
    while (1) {
        int ret = ebpfdivert_recv(h, &buf, sizeof(buf), 100);
        if (ret == 0) {
            const char *dir_str = (buf.header.direction == 1) ? "INGRESS" : "EGRESS";
            const char *proto_str = "UNKNOWN";
            
            uint8_t proto = 0;
            if (buf.header.l2_len + 20 <= buf.header.pkt_len) {
                uint8_t *l3 = buf.data + buf.header.l2_len;
                uint8_t ver = l3[0] >> 4;
                if (ver == 4) {
                    proto = l3[9];
                } else if (ver == 6) {
                    proto = l3[6];
                }
            }
            
            if (proto == 6) proto_str = "TCP";
            else if (proto == 17) proto_str = "UDP";
            else if (proto == 1) proto_str = "ICMP";
            else if (proto == 58) proto_str = "ICMPv6";
            
            printf("[%7s] IfIndex: %u, Len: %u, L2: %u, Proto: %s (%u)\n", 
                   dir_str, buf.header.ifindex, buf.header.pkt_len, buf.header.l2_len, proto_str, proto);
            
            if (pcap_file) {
                write_pcap_packet(pcap_file, &buf);
                fflush(pcap_file);
            }
        } else if (ret == -EAGAIN) {
            continue;
        } else if (ret == -EINTR || ret == -2) {
            continue;
        } else {
            fprintf(stderr, "ERROR: receiving packet failed: %s\n", strerror(-ret));
            break;
        }
    }
    
    if (pcap_file) {
        fclose(pcap_file);
    }
    ebpfdivert_close(h);
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }

    const char *cmd = argv[1];

    if (strcmp(cmd, "load") == 0) {
        const char *ifname = NULL;
        uint32_t priority = 0;
        const char *obj_path = "ebpfdivert.bpf.o";

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
        const char *pcap_filename = (argc >= 3) ? argv[2] : NULL;
        return cli_sniff(pcap_filename) ? 1 : 0;
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
