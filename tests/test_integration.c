// SPDX-License-Identifier: GPL-2.0-or-later OR LGPL-3.0-or-later
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <assert.h>
#include "ebpfdivert.h"

#define TEST_PORT 12345

// Helper to create a UDP server socket with a receive timeout
int create_udp_server(const char *ip_str, uint16_t port, int ipv6) {
    int fd = socket(ipv6 ? AF_INET6 : AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        perror("socket");
        return -1;
    }
    
    int opt = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        perror("setsockopt SO_REUSEADDR");
        close(fd);
        return -1;
    }
    
    struct timeval tv;
    tv.tv_sec = 0;
    tv.tv_usec = 200000; // 200ms timeout
    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) {
        perror("setsockopt SO_RCVTIMEO");
        close(fd);
        return -1;
    }
    
    if (ipv6) {
        struct sockaddr_in6 addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin6_family = AF_INET6;
        addr.sin6_port = htons(port);
        if (inet_pton(AF_INET6, ip_str, &addr.sin6_addr) != 1) {
            fprintf(stderr, "inet_pton failed for %s\n", ip_str);
            close(fd);
            return -1;
        }
        if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
            perror("bind ipv6");
            close(fd);
            return -1;
        }
    } else {
        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);
        addr.sin_addr.s_addr = inet_addr(ip_str);
        if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
            perror("bind ipv4");
            close(fd);
            return -1;
        }
    }
    return fd;
}

// Helper to create a UDP client socket (optionally bound to a specific source IP)
int create_udp_client(const char *bind_ip_str, int ipv6) {
    int fd = socket(ipv6 ? AF_INET6 : AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        perror("socket");
        return -1;
    }
    
    if (bind_ip_str) {
        if (ipv6) {
            struct sockaddr_in6 addr;
            memset(&addr, 0, sizeof(addr));
            addr.sin6_family = AF_INET6;
            if (inet_pton(AF_INET6, bind_ip_str, &addr.sin6_addr) != 1) {
                close(fd);
                return -1;
            }
            if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
                perror("bind client ipv6");
                close(fd);
                return -1;
            }
        } else {
            struct sockaddr_in addr;
            memset(&addr, 0, sizeof(addr));
            addr.sin_family = AF_INET;
            addr.sin_addr.s_addr = inet_addr(bind_ip_str);
            if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
                perror("bind client ipv4");
                close(fd);
                return -1;
            }
        }
    }
    return fd;
}

// Helper to send a UDP packet
int send_udp_packet(int client_fd, const char *dest_ip_str, uint16_t port, const char *payload, int ipv6) {
    size_t len = strlen(payload);
    if (ipv6) {
        struct sockaddr_in6 addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin6_family = AF_INET6;
        addr.sin6_port = htons(port);
        if (inet_pton(AF_INET6, dest_ip_str, &addr.sin6_addr) != 1) {
            return -1;
        }
        return sendto(client_fd, payload, len, 0, (struct sockaddr *)&addr, sizeof(addr));
    } else {
        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);
        addr.sin_addr.s_addr = inet_addr(dest_ip_str);
        return sendto(client_fd, payload, len, 0, (struct sockaddr *)&addr, sizeof(addr));
    }
}

// Helper to receive a UDP packet
int recv_udp_packet(int server_fd, char *buf, size_t buf_len) {
    ssize_t ret = recv(server_fd, buf, buf_len - 1, 0);
    if (ret >= 0) {
        buf[ret] = '\0';
        return ret;
    }
    return -1;
}

// Extract UDP payload from a raw divert packet buffer
const char *get_udp_payload(const struct divert_packet_buffer *buf, size_t *len) {
    uint16_t l2_len = buf->header.l2_len;
    if ((uint32_t)(l2_len + 20) > buf->header.pkt_len) return NULL;
    
    const uint8_t *l3 = buf->data + l2_len;
    uint8_t ver = l3[0] >> 4;
    
    if (ver == 4) {
        uint8_t ihl = l3[0] & 0x0F;
        if (ihl < 5) return NULL;
        uint16_t ip_header_len = ihl * 4;
        uint8_t proto = l3[9];
        if (proto != 17) return NULL; // Not UDP
        
        if ((uint32_t)(l2_len + ip_header_len + 8) > buf->header.pkt_len) return NULL;
        const uint8_t *udp = l3 + ip_header_len;
        uint16_t udp_len = ntohs(*(const uint16_t *)(udp + 4));
        if (udp_len < 8) return NULL;
        *len = udp_len - 8;
        return (const char *)(udp + 8);
    } else if (ver == 6) {
        uint8_t proto = l3[6];
        if (proto != 17) return NULL; // Not UDP
        
        if ((uint32_t)(l2_len + 40 + 8) > buf->header.pkt_len) return NULL;
        const uint8_t *udp = l3 + 40;
        uint16_t udp_len = ntohs(*(const uint16_t *)(udp + 4));
        if (udp_len < 8) return NULL;
        *len = udp_len - 8;
        return (const char *)(udp + 8);
    }
    return NULL;
}

void verify_stats_incremented(uint64_t *before, uint64_t *after, int stat_idx, const char *name) {
    if (after[stat_idx] > before[stat_idx]) {
        printf("  [PASS] Telemetry metric '%s' incremented correctly (before: %lu, after: %lu)\n", name, before[stat_idx], after[stat_idx]);
    } else {
        printf("  [FAIL] Telemetry metric '%s' did not increment (before: %lu, after: %lu)\n", name, before[stat_idx], after[stat_idx]);
        exit(1);
    }
}

void test_loopback_suite(void) {
    printf("\n=== Running Loopback Interface Suite ('lo') ===\n");
    
    // 1. Load ebpfdivert driver on lo
    if (ebpfdivert_load("lo", "ebpfdivert.bpf.o", 0) != 0) {
        fprintf(stderr, "ERROR: failed to load BPF program on 'lo'\n");
        exit(1);
    }
    printf("Successfully loaded ebpfdivert BPF program on 'lo'\n");

    // 2. Open handle
    ebpfdivert_handle_t *h = ebpfdivert_open(0);
    if (!h) {
        fprintf(stderr, "ERROR: failed to open ebpfdivert handle\n");
        ebpfdivert_unload("lo");
        exit(1);
    }

    struct divert_packet_buffer buf;
    char payload_buf[256];
    uint64_t stats_before[6] = {0}, stats_after[6] = {0};

    // --- Case 1: Divert & Drop ---
    printf("\nCase 1: Divert & Drop (IPv4)\n");
    ebpfdivert_rules_clear();
    ebpfdivert_rules_add(0, "udp", "any", "12345", "divert");
    ebpfdivert_get_stats(stats_before, 6);

    int srv = create_udp_server("127.0.0.1", TEST_PORT, 0);
    int cli = create_udp_client("127.0.0.1", 0);
    assert(srv >= 0 && cli >= 0);

    const char *payload1 = "loopback_divert_drop";
    send_udp_packet(cli, "127.0.0.1", TEST_PORT, payload1, 0);

    // Receiver should NOT get it
    int srv_ret = recv_udp_packet(srv, payload_buf, sizeof(payload_buf));
    if (srv_ret >= 0) {
        printf("  [FAIL] Receiver received packet that should be diverted/dropped\n");
        exit(1);
    }
    printf("  [PASS] Packet correctly diverted (receiver got nothing)\n");

    // Retrieve from ebpfdivert ringbuffer
    int recv_ret = ebpfdivert_recv(h, &buf, sizeof(buf), 200);
    if (recv_ret != 0) {
        printf("  [FAIL] ebpfdivert_recv failed to retrieve packet (ret: %d)\n", recv_ret);
        exit(1);
    }
    size_t payload_len = 0;
    const char *bpf_payload = get_udp_payload(&buf, &payload_len);
    if (!bpf_payload || strncmp(bpf_payload, payload1, payload_len) != 0) {
        printf("  [FAIL] Retrieved packet payload mismatch (got '%s')\n", bpf_payload ? bpf_payload : "NULL");
        exit(1);
    }
    printf("  [PASS] Successfully retrieved diverted packet from ringbuffer (payload matches)\n");

    ebpfdivert_get_stats(stats_after, 6);
    verify_stats_incremented(stats_before, stats_after, STAT_DIVERTED, "STAT_DIVERTED");

    close(srv);
    close(cli);

    // --- Case 2: Drop Rule ---
    printf("\nCase 2: Drop Rule\n");
    ebpfdivert_rules_clear();
    ebpfdivert_rules_add(0, "udp", "any", "12345", "drop");
    ebpfdivert_get_stats(stats_before, 6);

    srv = create_udp_server("127.0.0.1", TEST_PORT, 0);
    cli = create_udp_client("127.0.0.1", 0);
    assert(srv >= 0 && cli >= 0);

    const char *payload2 = "loopback_drop_rule";
    send_udp_packet(cli, "127.0.0.1", TEST_PORT, payload2, 0);

    // Receiver should get nothing
    srv_ret = recv_udp_packet(srv, payload_buf, sizeof(payload_buf));
    if (srv_ret >= 0) {
        printf("  [FAIL] Receiver received packet matching Drop rule\n");
        exit(1);
    }
    
    // User-space queue should get nothing
    recv_ret = ebpfdivert_recv(h, &buf, sizeof(buf), 100);
    if (recv_ret == 0) {
        printf("  [FAIL] User space received packet matching Drop rule\n");
        exit(1);
    }
    printf("  [PASS] Packet matching Drop rule was dropped silently\n");

    ebpfdivert_get_stats(stats_after, 6);
    verify_stats_incremented(stats_before, stats_after, STAT_DROPPED, "STAT_DROPPED");

    close(srv);
    close(cli);

    // --- Case 3: Sniff Rule ---
    printf("\nCase 3: Sniff Rule\n");
    ebpfdivert_rules_clear();
    ebpfdivert_rules_add(0, "udp", "any", "12345", "sniff");
    ebpfdivert_get_stats(stats_before, 6);

    srv = create_udp_server("127.0.0.1", TEST_PORT, 0);
    cli = create_udp_client("127.0.0.1", 0);
    assert(srv >= 0 && cli >= 0);

    const char *payload3 = "loopback_sniff_rule";
    send_udp_packet(cli, "127.0.0.1", TEST_PORT, payload3, 0);

    // Receiver should get it normally
    srv_ret = recv_udp_packet(srv, payload_buf, sizeof(payload_buf));
    if (srv_ret < 0 || strcmp(payload_buf, payload3) != 0) {
        printf("  [FAIL] Receiver failed to get sniffed packet\n");
        exit(1);
    }
    printf("  [PASS] Receiver successfully received sniffed packet\n");

    // User space should ALSO get it (twice on loopback due to bidirectional matching)
    recv_ret = ebpfdivert_recv(h, &buf, sizeof(buf), 200);
    if (recv_ret != 0) {
        printf("  [FAIL] User space failed to receive copy of sniffed packet (1)\n");
        exit(1);
    }
    recv_ret = ebpfdivert_recv(h, &buf, sizeof(buf), 200);
    if (recv_ret != 0) {
        printf("  [FAIL] User space failed to receive copy of sniffed packet (2)\n");
        exit(1);
    }
    printf("  [PASS] User space successfully captured copy of sniffed packet\n");

    ebpfdivert_get_stats(stats_after, 6);
    verify_stats_incremented(stats_before, stats_after, STAT_SNIFFED, "STAT_SNIFFED");

    close(srv);
    close(cli);

    // --- Case 4: No Match / Normal Flow ---
    printf("\nCase 4: No Match / Normal Flow\n");
    ebpfdivert_rules_clear();
    ebpfdivert_rules_add(0, "udp", "any", "9999", "divert"); // Unrelated rule

    srv = create_udp_server("127.0.0.1", TEST_PORT, 0);
    cli = create_udp_client("127.0.0.1", 0);
    assert(srv >= 0 && cli >= 0);

    const char *payload4 = "loopback_no_match";
    send_udp_packet(cli, "127.0.0.1", TEST_PORT, payload4, 0);

    // Receiver gets it
    srv_ret = recv_udp_packet(srv, payload_buf, sizeof(payload_buf));
    if (srv_ret < 0 || strcmp(payload_buf, payload4) != 0) {
        printf("  [FAIL] Receiver failed to get unmatched packet\n");
        exit(1);
    }
    printf("  [PASS] Receiver got unmatched packet normally\n");

    // User space gets nothing
    recv_ret = ebpfdivert_recv(h, &buf, sizeof(buf), 100);
    if (recv_ret == 0) {
        printf("  [FAIL] User space mistakenly captured unmatched packet\n");
        exit(1);
    }
    printf("  [PASS] Unmatched packet skipped by BPF engine\n");

    close(srv);
    close(cli);

    // --- Case 5: Multiple packets back-to-back ---
    printf("\nCase 5: Multiple packets back-to-back\n");
    ebpfdivert_rules_clear();
    ebpfdivert_rules_add(0, "udp", "any", "12345", "divert");
    ebpfdivert_get_stats(stats_before, 6);

    srv = create_udp_server("127.0.0.1", TEST_PORT, 0);
    cli = create_udp_client("127.0.0.1", 0);
    assert(srv >= 0 && cli >= 0);

    const char *payload_multi1 = "loopback_multi_1";
    const char *payload_multi2 = "loopback_multi_2";
    send_udp_packet(cli, "127.0.0.1", TEST_PORT, payload_multi1, 0);
    send_udp_packet(cli, "127.0.0.1", TEST_PORT, payload_multi2, 0);

    // Both should be diverted, so receiver gets nothing
    srv_ret = recv_udp_packet(srv, payload_buf, sizeof(payload_buf));
    if (srv_ret >= 0) {
        printf("  [FAIL] Receiver received packet that should be diverted/dropped (1)\n");
        exit(1);
    }
    srv_ret = recv_udp_packet(srv, payload_buf, sizeof(payload_buf));
    if (srv_ret >= 0) {
        printf("  [FAIL] Receiver received packet that should be diverted/dropped (2)\n");
        exit(1);
    }
    printf("  [PASS] Both packets correctly diverted (receiver got nothing)\n");

    // Retrieve first packet from ebpfdivert ringbuffer
    recv_ret = ebpfdivert_recv(h, &buf, sizeof(buf), 200);
    if (recv_ret != 0) {
        printf("  [FAIL] ebpfdivert_recv failed to retrieve first packet (ret: %d)\n", recv_ret);
        exit(1);
    }
    payload_len = 0;
    bpf_payload = get_udp_payload(&buf, &payload_len);
    if (!bpf_payload || strncmp(bpf_payload, payload_multi1, payload_len) != 0) {
        printf("  [FAIL] First retrieved packet payload mismatch (got '%s')\n", bpf_payload ? bpf_payload : "NULL");
        exit(1);
    }
    printf("  [PASS] Successfully retrieved first packet from ringbuffer (payload matches)\n");

    // Retrieve second packet from ebpfdivert ringbuffer
    recv_ret = ebpfdivert_recv(h, &buf, sizeof(buf), 200);
    if (recv_ret != 0) {
        printf("  [FAIL] ebpfdivert_recv failed to retrieve second packet (ret: %d)\n", recv_ret);
        exit(1);
    }
    payload_len = 0;
    bpf_payload = get_udp_payload(&buf, &payload_len);
    if (!bpf_payload || strncmp(bpf_payload, payload_multi2, payload_len) != 0) {
        printf("  [FAIL] Second retrieved packet payload mismatch (got '%s')\n", bpf_payload ? bpf_payload : "NULL");
        exit(1);
    }
    printf("  [PASS] Successfully retrieved second packet from ringbuffer (payload matches)\n");

    ebpfdivert_get_stats(stats_after, 6);
    // Since both were diverted, STAT_DIVERTED should be incremented by 2
    if (stats_after[STAT_DIVERTED] == stats_before[STAT_DIVERTED] + 2) {
        printf("  [PASS] Telemetry metric 'STAT_DIVERTED' incremented correctly by 2 (before: %lu, after: %lu)\n", stats_before[STAT_DIVERTED], stats_after[STAT_DIVERTED]);
    } else {
        printf("  [FAIL] Telemetry metric 'STAT_DIVERTED' did not increment by 2 (before: %lu, after: %lu)\n", stats_before[STAT_DIVERTED], stats_after[STAT_DIVERTED]);
        exit(1);
    }

    close(srv);
    close(cli);

    // --- Case 6: Active Backpressure ---
    printf("\nCase 6: Active Backpressure\n");
    ebpfdivert_rules_clear();
    ebpfdivert_rules_add(0, "udp", "any", "12345", "divert");
    ebpfdivert_get_stats(stats_before, 6);

    // Limit queue size to 2
    ebpfdivert_set_max_queue_size(h, 2);

    srv = create_udp_server("127.0.0.1", TEST_PORT, 0);
    cli = create_udp_client("127.0.0.1", 0);
    assert(srv >= 0 && cli >= 0);

    const char *payload_bp1 = "bp_pkt_1";
    const char *payload_bp2 = "bp_pkt_2";
    const char *payload_bp3 = "bp_pkt_3";
    const char *payload_bp4 = "bp_pkt_4";

    send_udp_packet(cli, "127.0.0.1", TEST_PORT, payload_bp1, 0);
    send_udp_packet(cli, "127.0.0.1", TEST_PORT, payload_bp2, 0);
    send_udp_packet(cli, "127.0.0.1", TEST_PORT, payload_bp3, 0);
    send_udp_packet(cli, "127.0.0.1", TEST_PORT, payload_bp4, 0);
    usleep(50000); // Wait for BPF to process

    // Call recv to trigger polling
    recv_ret = ebpfdivert_recv(h, &buf, sizeof(buf), 100);
    if (recv_ret != 0) {
        printf("  [FAIL] Failed to receive first backpressure packet (ret: %d)\n", recv_ret);
        exit(1);
    }
    
    // We should receive 1, and 2 and 3 should be in queue. 4 should be dropped.
    ebpfdivert_get_stats(stats_after, 6);
    verify_stats_incremented(stats_before, stats_after, STAT_QUEUE_FULL, "STAT_QUEUE_FULL");

    // Pop the rest from queue
    recv_ret = ebpfdivert_recv(h, &buf, sizeof(buf), 100); // returns 2
    assert(recv_ret == 0);
    recv_ret = ebpfdivert_recv(h, &buf, sizeof(buf), 100); // returns 3
    assert(recv_ret == 0);
    
    // Queue should now be empty. Trying to receive again should timeout.
    recv_ret = ebpfdivert_recv(h, &buf, sizeof(buf), 100);
    if (recv_ret == 0) {
        printf("  [FAIL] Received 4th packet which should have been dropped due to queue limit\n");
        exit(1);
    }
    printf("  [PASS] Queue bounds enforced: 4th packet successfully dropped and telemetried\n");

    // Restore max queue size
    ebpfdivert_set_max_queue_size(h, 1024);

    close(srv);
    close(cli);

    // Teardown
    ebpfdivert_close(h);
    ebpfdivert_unload("lo");
    printf("\n=== Loopback Suite PASSED ===\n");
}

pid_t run_ns_server(const char *expected_payload, const char *out_file) {
    pid_t pid = fork();
    if (pid == 0) {
        char port_str[16];
        snprintf(port_str, sizeof(port_str), "%d", TEST_PORT);
        execlp("ip", "ip", "netns", "exec", "ns1", "./test_integration", "server", "10.200.1.2", port_str, expected_payload, out_file, NULL);
        perror("execlp ip netns exec");
        exit(1);
    }
    return pid;
}

void test_veth_suite(const char *veth0) {
    printf("\n=== Running External/Veth Interface Suite ('%s' <-> 'ns1/veth_test1') ===\n", veth0);
    
    // We attach the driver on veth0.
    if (ebpfdivert_load(veth0, "ebpfdivert.bpf.o", 0) != 0) {
        fprintf(stderr, "ERROR: failed to load BPF program on '%s'\n", veth0);
        exit(1);
    }
    printf("Successfully loaded ebpfdivert BPF program on '%s'\n", veth0);

    ebpfdivert_handle_t *h = ebpfdivert_open(0);
    if (!h) {
        fprintf(stderr, "ERROR: failed to open handle\n");
        ebpfdivert_unload(veth0);
        exit(1);
    }

    struct divert_packet_buffer buf;
    uint64_t stats_before[6] = {0}, stats_after[6] = {0};

    // --- Case 1: Egress Divert & Reinject (external link) ---
    printf("\nCase 1: Egress Divert & Reinject\n");
    ebpfdivert_rules_clear();
    ebpfdivert_rules_add(0, "udp", "10.200.1.2/32", "12345", "divert");
    ebpfdivert_get_stats(stats_before, 6);

    const char *payload1 = "veth_egress_reinject";
    const char *rx_file = "/tmp/veth_rx.txt";
    unlink(rx_file);

    // Start background UDP server inside netns ns1
    pid_t srv_pid = run_ns_server(payload1, rx_file);
    usleep(150000); // 150ms wait for server to bind

    // Client on host namespace bound to veth0
    int cli = create_udp_client("10.200.1.1", 0);
    assert(cli >= 0);
    send_udp_packet(cli, "10.200.1.2", TEST_PORT, payload1, 0);

    // Capture in user space
    int recv_ret = ebpfdivert_recv(h, &buf, sizeof(buf), 300);
    if (recv_ret != 0) {
        printf("  [FAIL] ebpfdivert_recv failed to capture egress packet (ret: %d)\n", recv_ret);
        kill(srv_pid, SIGKILL);
        exit(1);
    }
    size_t payload_len = 0;
    const char *bpf_payload = get_udp_payload(&buf, &payload_len);
    if (!bpf_payload || strncmp(bpf_payload, payload1, payload_len) != 0) {
        printf("  [FAIL] Payload mismatch (got '%s')\n", bpf_payload ? bpf_payload : "NULL");
        kill(srv_pid, SIGKILL);
        exit(1);
    }
    printf("  [PASS] Successfully captured egress packet in user-space\n");

    // Reinject on veth0
    int send_ret = ebpfdivert_send(h, &buf);
    if (send_ret != 0) {
        printf("  [FAIL] ebpfdivert_send failed to reinject (ret: %d)\n", send_ret);
        kill(srv_pid, SIGKILL);
        exit(1);
    }

    // Wait for server to receive packet and exit
    int status;
    waitpid(srv_pid, &status, 0);

    // Read result
    FILE *f = fopen(rx_file, "r");
    char result_buf[256] = {0};
    if (f) {
        if (!fgets(result_buf, sizeof(result_buf), f)) {
            result_buf[0] = '\0';
        }
        fclose(f);
    }
    if (strcmp(result_buf, "SUCCESS") != 0) {
        printf("  [FAIL] Server helper did not receive reinjected packet (result: '%s')\n", result_buf);
        exit(1);
    }
    printf("  [PASS] Egress packet reinjected successfully and received by netns server\n");

    ebpfdivert_get_stats(stats_after, 6);
    verify_stats_incremented(stats_before, stats_after, STAT_DIVERTED, "STAT_DIVERTED");

    close(cli);

    // --- Case 2: Drop Rule on Egress ---
    printf("\nCase 2: Drop Rule on Egress\n");
    ebpfdivert_rules_clear();
    ebpfdivert_rules_add(0, "udp", "10.200.1.2/32", "12345", "drop");
    ebpfdivert_get_stats(stats_before, 6);

    const char *payload2 = "veth_egress_drop";
    unlink(rx_file);
    srv_pid = run_ns_server(payload2, rx_file);
    usleep(150000);

    cli = create_udp_client("10.200.1.1", 0);
    assert(cli >= 0);
    send_udp_packet(cli, "10.200.1.2", TEST_PORT, payload2, 0);

    // Wait for server to time out (since packet is dropped)
    waitpid(srv_pid, &status, 0);

    f = fopen(rx_file, "r");
    result_buf[0] = '\0';
    if (f) {
        if (!fgets(result_buf, sizeof(result_buf), f)) {
            result_buf[0] = '\0';
        }
        fclose(f);
    }
    if (strncmp(result_buf, "FAIL", 4) != 0) {
        printf("  [FAIL] Server helper received dropped packet (result: '%s')\n", result_buf);
        exit(1);
    }
    printf("  [PASS] Packet dropped on egress successfully (server helper timed out)\n");

    ebpfdivert_get_stats(stats_after, 6);
    verify_stats_incremented(stats_before, stats_after, STAT_DROPPED, "STAT_DROPPED");

    close(cli);

    // --- Case 3: Sniff Rule on Egress ---
    printf("\nCase 3: Sniff Rule on Egress\n");
    ebpfdivert_rules_clear();
    ebpfdivert_rules_add(0, "udp", "10.200.1.2/32", "12345", "sniff");
    ebpfdivert_get_stats(stats_before, 6);

    const char *payload3 = "veth_egress_sniff";
    unlink(rx_file);
    srv_pid = run_ns_server(payload3, rx_file);
    usleep(150000);

    cli = create_udp_client("10.200.1.1", 0);
    assert(cli >= 0);
    send_udp_packet(cli, "10.200.1.2", TEST_PORT, payload3, 0);

    // Wait for server (should get it)
    waitpid(srv_pid, &status, 0);

    f = fopen(rx_file, "r");
    result_buf[0] = '\0';
    if (f) {
        if (!fgets(result_buf, sizeof(result_buf), f)) {
            result_buf[0] = '\0';
        }
        fclose(f);
    }
    if (strcmp(result_buf, "SUCCESS") != 0) {
        printf("  [FAIL] Server helper failed to receive sniffed packet (result: '%s')\n", result_buf);
        exit(1);
    }
    printf("  [PASS] Server helper got sniffed packet successfully\n");

    // BPF should also get a copy
    recv_ret = ebpfdivert_recv(h, &buf, sizeof(buf), 200);
    if (recv_ret != 0) {
        printf("  [FAIL] User space failed to capture sniffed packet copy\n");
        exit(1);
    }
    printf("  [PASS] User space successfully sniffed packet copy\n");

    ebpfdivert_get_stats(stats_after, 6);
    verify_stats_incremented(stats_before, stats_after, STAT_SNIFFED, "STAT_SNIFFED");

    close(cli);

    // --- Case 4: Ingress Divert & Redirect Reinject ---
    printf("\nCase 4: Ingress Divert & Redirect Reinject\n");
    ebpfdivert_rules_clear();
    struct ebpfdivert_rule_opt opt = {
        .proto = "udp",
        .dst_port_range = "12345",
        .direction = "ingress",
        .action = "divert"
    };
    ebpfdivert_rules_add_extended(0, &opt);
    ebpfdivert_get_stats(stats_before, 6);

    const char *payload4 = "veth_ingress_redirect";

    int host_srv = create_udp_server("10.200.1.1", TEST_PORT, 0);
    assert(host_srv >= 0);

    pid_t ns_cli_pid = fork();
    if (ns_cli_pid == 0) {
        char port_str[16];
        snprintf(port_str, sizeof(port_str), "%d", TEST_PORT);
        execlp("ip", "ip", "netns", "exec", "ns1", "./test_integration", "client", "10.200.1.1", port_str, payload4, "10.200.1.2", NULL);
        perror("execlp ip netns exec client");
        exit(1);
    }

    recv_ret = ebpfdivert_recv(h, &buf, sizeof(buf), 500);
    if (recv_ret != 0) {
        printf("  [FAIL] ebpfdivert_recv failed to capture ingress packet (ret: %d)\n", recv_ret);
        kill(ns_cli_pid, SIGKILL);
        close(host_srv);
        exit(1);
    }

    payload_len = 0;
    bpf_payload = get_udp_payload(&buf, &payload_len);
    if (!bpf_payload || strncmp(bpf_payload, payload4, payload_len) != 0) {
        printf("  [FAIL] Ingress payload mismatch (got '%s')\n", bpf_payload ? bpf_payload : "NULL");
        kill(ns_cli_pid, SIGKILL);
        close(host_srv);
        exit(1);
    }
    printf("  [PASS] Successfully captured ingress packet in user-space\n");

    send_ret = ebpfdivert_send(h, &buf);
    if (send_ret != 0) {
        printf("  [FAIL] ebpfdivert_send failed to reinject ingress packet (ret: %d)\n", send_ret);
        kill(ns_cli_pid, SIGKILL);
        close(host_srv);
        exit(1);
    }

    char host_rx_buf[256];
    int host_rx_len = recv_udp_packet(host_srv, host_rx_buf, sizeof(host_rx_buf));
    if (host_rx_len < 0 || strcmp(host_rx_buf, payload4) != 0) {
        printf("  [FAIL] Host server did not receive the redirected ingress packet (ret: %d, got '%s')\n", host_rx_len, host_rx_buf);
        kill(ns_cli_pid, SIGKILL);
        close(host_srv);
        exit(1);
    }
    printf("  [PASS] Host server successfully received redirected ingress packet!\n");

    int ns_cli_status;
    waitpid(ns_cli_pid, &ns_cli_status, 0);

    ebpfdivert_get_stats(stats_after, 6);
    verify_stats_incremented(stats_before, stats_after, STAT_DIVERTED, "STAT_DIVERTED");

    close(host_srv);

    // Teardown
    ebpfdivert_close(h);
    ebpfdivert_unload(veth0);
    printf("\n=== External/Veth Suite PASSED ===\n");
}

int run_server(const char *ip_str, uint16_t port, const char *expected_payload, const char *out_file) {
    int fd = create_udp_server(ip_str, port, 0);
    if (fd < 0) {
        FILE *f = fopen(out_file, "w");
        if (f) {
            fprintf(f, "ERROR_BIND");
            fclose(f);
        }
        return 1;
    }
    
    char buf[256];
    int ret = recv_udp_packet(fd, buf, sizeof(buf));
    close(fd);
    
    FILE *f = fopen(out_file, "w");
    if (!f) return 1;
    
    if (ret >= 0 && strcmp(buf, expected_payload) == 0) {
        fprintf(f, "SUCCESS");
    } else {
        fprintf(f, "FAIL: ret=%d, payload='%s'", ret, buf);
    }
    fclose(f);
    return 0;
}

int run_client(const char *dest_ip, uint16_t port, const char *payload, const char *bind_ip) {
    int fd = create_udp_client(bind_ip, 0);
    if (fd < 0) return 1;
    int ret = send_udp_packet(fd, dest_ip, port, payload, 0);
    close(fd);
    return ret >= 0 ? 0 : 1;
}

int main(int argc, char **argv) {
    if (argc >= 6 && strcmp(argv[1], "server") == 0) {
        return run_server(argv[2], atoi(argv[3]), argv[4], argv[5]);
    }
    
    if (argc >= 5 && strcmp(argv[1], "client") == 0) {
        const char *bind_ip = (argc >= 6) ? argv[5] : NULL;
        return run_client(argv[2], atoi(argv[3]), argv[4], bind_ip);
    }
    
    if (argc >= 3 && strcmp(argv[1], "lo") == 0) {
        test_loopback_suite();
        test_veth_suite(argv[2]);
    } else {
        test_loopback_suite();
    }
    
    printf("\n[SUCCESS] All eBPFDivert integration tests passed!\n");
    return 0;
}
