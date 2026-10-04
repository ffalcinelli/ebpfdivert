// SPDX-License-Identifier: GPL-2.0-or-later OR LGPL-3.0-or-later
/*
 * test_integration - end-to-end tests of the libebpfdivert handle API.
 *
 * Topology (created by tests/run_integration_tests.sh):
 *
 *   ns1: veth_test1 10.200.1.2 fd00:1::2
 *          |
 *   root: veth_test0 10.200.1.1 fd00:1::1   (ip_forward=1)
 *         veth_test2 10.200.2.1
 *          |
 *   ns2: veth_test3 10.200.2.2
 *
 * Offloads (TSO/GSO/GRO) are left enabled on purpose.  Needs root.
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <poll.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "ebpfdivert.h"

static int failures, passes;

#define CHECK(cond, ...)                                        \
    do {                                                        \
        if (cond) {                                             \
            passes++;                                           \
        } else {                                                \
            failures++;                                         \
            fprintf(stderr, "  [FAIL] %s:%d: ", __func__, __LINE__); \
            fprintf(stderr, __VA_ARGS__);                       \
            fprintf(stderr, "\n");                              \
        }                                                       \
    } while (0)

static uint8_t pkt[EBPFDIVERT_MTU_MAX];

/****************************************************************************/
/* Socket helpers                                                           */
/****************************************************************************/

static int enter_ns(const char *ns)
{
    char path[128];
    int fd;
    snprintf(path, sizeof(path), "/var/run/netns/%s", ns);
    fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0 || setns(fd, CLONE_NEWNET) != 0) {
        perror("setns");
        return -1;
    }
    close(fd);
    return 0;
}

static int sockaddr_of(const char *ip, uint16_t port, struct sockaddr_storage *ss, socklen_t *len)
{
    memset(ss, 0, sizeof(*ss));
    if (strchr(ip, ':')) {
        struct sockaddr_in6 *a = (struct sockaddr_in6 *)ss;
        a->sin6_family = AF_INET6;
        a->sin6_port = htons(port);
        *len = sizeof(*a);
        return inet_pton(AF_INET6, ip, &a->sin6_addr) == 1 ? AF_INET6 : -1;
    } else {
        struct sockaddr_in *a = (struct sockaddr_in *)ss;
        a->sin_family = AF_INET;
        a->sin_port = htons(port);
        *len = sizeof(*a);
        return inet_pton(AF_INET, ip, &a->sin_addr) == 1 ? AF_INET : -1;
    }
}

static int udp_bind(const char *ip, uint16_t port, int timeout_ms)
{
    struct sockaddr_storage ss;
    socklen_t len;
    struct timeval tv = {timeout_ms / 1000, (timeout_ms % 1000) * 1000};
    int one = 1, fam = sockaddr_of(ip, port, &ss, &len), fd;
    fd = socket(fam, SOCK_DGRAM, 0);
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    if (bind(fd, (struct sockaddr *)&ss, len) != 0) {
        perror("bind");
        close(fd);
        return -1;
    }
    return fd;
}

static int udp_send(const char *ip, uint16_t port, const void *data, size_t n)
{
    struct sockaddr_storage ss;
    socklen_t len;
    int fam = sockaddr_of(ip, port, &ss, &len), fd = socket(fam, SOCK_DGRAM, 0);
    ssize_t r = sendto(fd, data, n, 0, (struct sockaddr *)&ss, len);
    close(fd);
    return r == (ssize_t)n ? 0 : -1;
}

/* Receive one datagram; returns its length or -1 on timeout. */
static int udp_recv(int fd, char *buf, size_t n)
{
    ssize_t r = recv(fd, buf, n - 1, 0);
    if (r < 0)
        return -1;
    buf[r] = '\0';
    return (int)r;
}

/* A TCP socket that fails within seconds instead of hanging a test run. */
static int tcp_socket(void)
{
    struct timeval tv = {5, 0};
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    return fd;
}

/* Fork a child in `ns` that runs fn(arg) and writes its result to a pipe. */
struct child {
    pid_t pid;
    int rfd;
};

static struct child spawn_in_ns(const char *ns, void (*fn)(int wfd, void *arg), void *arg)
{
    struct child c = {-1, -1};
    int p[2];
    if (pipe(p) != 0)
        return c;
    c.pid = fork();
    if (c.pid == 0) {
        close(p[0]);
        if (ns && enter_ns(ns) != 0)
            _exit(1);
        fn(p[1], arg);
        _exit(0);
    }
    close(p[1]);
    c.rfd = p[0];
    return c;
}

static int child_result(struct child *c, char *buf, size_t n)
{
    ssize_t r, total = 0;
    while ((r = read(c->rfd, buf + total, n - 1 - (size_t)total)) > 0)
        total += r;
    buf[total] = '\0';
    close(c->rfd);
    waitpid(c->pid, NULL, 0);
    return (int)total;
}

struct udp_server_arg {
    const char *ip;
    uint16_t port;
    int timeout_ms;
    int ready_fd;
};

/* Child: receive one datagram, report its payload (or TIMEOUT). */
static void udp_server_child(int wfd, void *a)
{
    struct udp_server_arg *arg = a;
    char buf[2048];
    int fd = udp_bind(arg->ip, arg->port, arg->timeout_ms);
    char c = 1;
    if (write(arg->ready_fd, &c, 1) != 1)
        _exit(1);
    if (fd < 0 || udp_recv(fd, buf, sizeof(buf)) < 0)
        snprintf(buf, sizeof(buf), "TIMEOUT");
    if (write(wfd, buf, strlen(buf)) < 0)
        _exit(1);
}

static struct child start_udp_server(const char *ns, const char *ip, uint16_t port,
                                     int timeout_ms)
{
    static struct udp_server_arg arg;
    int ready[2];
    char c;
    struct child ch;
    if (pipe(ready) != 0) {
        struct child bad = {-1, -1};
        return bad;
    }
    arg.ip = ip;
    arg.port = port;
    arg.timeout_ms = timeout_ms;
    arg.ready_fd = ready[1];
    ch = spawn_in_ns(ns, udp_server_child, &arg);
    close(ready[1]);
    if (read(ready[0], &c, 1) != 1)
        fprintf(stderr, "server did not start\n");
    close(ready[0]);
    return ch;
}

struct udp_sender_arg {
    const char *ip;
    uint16_t port;
    const char *payload;
};

static void udp_sender_child(int wfd, void *a)
{
    struct udp_sender_arg *arg = a;
    (void)wfd;
    usleep(50000);
    udp_send(arg->ip, arg->port, arg->payload, strlen(arg->payload));
}

/****************************************************************************/
/* Handle helpers                                                           */
/****************************************************************************/

static ebpfdivert_handle_t *open_handle(const char *filter, int layer, int16_t prio,
                                        uint64_t flags, const char *ifname)
{
    const char *ifs[2] = {ifname, NULL};
    struct ebpfdivert_open_opts opts = {.sz = sizeof(opts), .ifnames = ifname ? ifs : NULL};
    ebpfdivert_handle_t *h = ebpfdivert_open(filter, layer, prio, flags, &opts);
    if (!h)
        fprintf(stderr, "  ebpfdivert_open('%s') failed: %s\n", filter, strerror(errno));
    return h;
}

/* Find `needle` in a packet's payload. */
static int contains(const uint8_t *p, uint32_t len, const char *needle)
{
    size_t n = strlen(needle);
    uint32_t i;
    for (i = 0; i + n <= len; i++)
        if (memcmp(p + i, needle, n) == 0)
            return 1;
    return 0;
}

/* A thread that re-injects everything a handle receives. */
struct reinjector {
    ebpfdivert_handle_t *h;
    pthread_t thread;
    volatile int stop;
    int count, inbound, outbound, impostors;
    uint32_t max_len;
};

static void *reinject_loop(void *a)
{
    struct reinjector *r = a;
    static __thread uint8_t buf[EBPFDIVERT_MTU_MAX];
    struct ebpfdivert_address addr;
    uint32_t len;
    while (!r->stop) {
        int ret = ebpfdivert_recv(r->h, buf, sizeof(buf), &len, &addr, 100);
        if (ret == -EAGAIN)
            continue;
        if (ret)
            break;
        r->count++;
        if (addr.outbound)
            r->outbound++;
        else
            r->inbound++;
        r->impostors += addr.impostor;
        if (len > r->max_len)
            r->max_len = len;
        ret = ebpfdivert_send(r->h, buf, len, NULL, &addr);
        if (ret)
            fprintf(stderr, "  reinject of %u bytes failed: %s\n", len, ebpfdivert_strerror(ret));
    }
    return NULL;
}

static void reinjector_start(struct reinjector *r, ebpfdivert_handle_t *h)
{
    memset(r, 0, sizeof(*r));
    r->h = h;
    pthread_create(&r->thread, NULL, reinject_loop, r);
}

static void reinjector_stop(struct reinjector *r)
{
    r->stop = 1;
    pthread_join(r->thread, NULL);
}

/****************************************************************************/
/* Tests                                                                    */
/****************************************************************************/

static void test_loopback_single_sighting(void)
{
    struct ebpfdivert_address addr;
    uint32_t len;
    char buf[256];
    int srv, ret;
    ebpfdivert_handle_t *h = open_handle("udp.DstPort == 12345", 0, 0, 0, NULL);
    if (!h)
        return;
    srv = udp_bind("127.0.0.1", 12345, 300);
    udp_send("127.0.0.1", 12345, "hello-lo", 8);

    ret = ebpfdivert_recv(h, pkt, sizeof(pkt), &len, &addr, 1000);
    CHECK(ret == 0, "recv: %s", ebpfdivert_strerror(ret));
    CHECK(addr.outbound && addr.loopback && !addr.impostor && !addr.sniffed,
          "flags out=%u lo=%u imp=%u sniff=%u", addr.outbound, addr.loopback, addr.impostor,
          addr.sniffed);
    CHECK(contains(pkt, len, "hello-lo"), "payload");
    CHECK(udp_recv(srv, buf, sizeof(buf)) < 0, "packet leaked before re-injection");
    CHECK(ebpfdivert_send(h, pkt, len, NULL, &addr) == 0, "send");
    CHECK(udp_recv(srv, buf, sizeof(buf)) > 0 && strcmp(buf, "hello-lo") == 0,
          "server did not get the re-injected packet");
    /* The same packet must not be reported again on lo ingress. */
    ret = ebpfdivert_recv(h, pkt, sizeof(pkt), &len, &addr, 300);
    CHECK(ret == -EAGAIN, "loopback packet seen twice (%d)", ret);
    close(srv);
    ebpfdivert_close(h);
}

struct tcp_echo_arg {
    uint16_t port;
    int ready_fd;
};

static void tcp_echo_child(int wfd, void *a)
{
    struct tcp_echo_arg *arg = a;
    struct sockaddr_in sa = {.sin_family = AF_INET, .sin_port = htons(arg->port)};
    int one = 1, fd = socket(AF_INET, SOCK_STREAM, 0), c;
    char buf[64], ok = 1;
    ssize_t n;
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) != 0 || listen(fd, 1) != 0)
        _exit(1);
    if (write(arg->ready_fd, &ok, 1) != 1)
        _exit(1);
    c = accept(fd, NULL, NULL);
    n = read(c, buf, sizeof(buf));
    if (n > 0 && write(c, buf, (size_t)n) != n)
        _exit(1);
    close(c);
    if (write(wfd, "done", 4) != 4)
        _exit(1);
}

/* tcp.Port matches both directions (the old transpiler only matched dst). */
static void test_tcp_port_both_directions(void)
{
    struct reinjector r;
    struct tcp_echo_arg arg = {.port = 12346};
    struct sockaddr_in sa = {.sin_family = AF_INET, .sin_port = htons(12346)};
    struct child srv;
    int ready[2], fd;
    char c, buf[64];
    ebpfdivert_handle_t *h = open_handle("tcp.DstPort == 12346 or tcp.SrcPort == 12346", 0, 0, 0,
                                         NULL);
    if (!h)
        return;
    reinjector_start(&r, h);
    if (pipe(ready) != 0)
        return;
    arg.ready_fd = ready[1];
    srv = spawn_in_ns(NULL, tcp_echo_child, &arg);
    close(ready[1]);
    if (read(ready[0], &c, 1) != 1)
        fprintf(stderr, "echo server failed\n");
    close(ready[0]);

    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    fd = tcp_socket();
    CHECK(connect(fd, (struct sockaddr *)&sa, sizeof(sa)) == 0, "connect: %s", strerror(errno));
    CHECK(write(fd, "ping", 4) == 4, "write");
    CHECK(read(fd, buf, sizeof(buf)) == 4, "echo not received");
    close(fd);
    child_result(&srv, buf, sizeof(buf));
    usleep(200000);
    reinjector_stop(&r);
    /* SYN, SYN-ACK, ACK, data both ways, FINs...: well over 6 packets. */
    CHECK(r.count >= 6, "only %d packets diverted", r.count);
    ebpfdivert_close(h);
}

/* Inbound on a real interface: re-injection goes through the lo redirect. */
static void test_inbound_veth(void)
{
    struct udp_sender_arg sarg = {"10.200.1.1", 12347, "hello-inbound"};
    struct ebpfdivert_address addr;
    struct child sender;
    uint32_t len;
    char buf[256];
    int srv, ret;
    ebpfdivert_handle_t *h = open_handle("inbound and udp.DstPort == 12347", 0, 0, 0,
                                         "veth_test0");
    if (!h)
        return;
    srv = udp_bind("10.200.1.1", 12347, 1000);
    sender = spawn_in_ns("ns1", udp_sender_child, &sarg);
    ret = ebpfdivert_recv(h, pkt, sizeof(pkt), &len, &addr, 2000);
    CHECK(ret == 0, "recv: %s", ebpfdivert_strerror(ret));
    CHECK(!addr.outbound && !addr.loopback, "direction/loopback");
    CHECK(addr.network.if_idx == if_nametoindex("veth_test0"), "if_idx %u", addr.network.if_idx);
    CHECK(contains(pkt, len, "hello-inbound"), "payload");
    CHECK(ebpfdivert_send(h, pkt, len, NULL, &addr) == 0, "send");
    CHECK(udp_recv(srv, buf, sizeof(buf)) > 0 && strcmp(buf, "hello-inbound") == 0,
          "re-injected inbound packet not delivered");
    child_result(&sender, buf, sizeof(buf));
    close(srv);
    ebpfdivert_close(h);
}

/* Outbound on a real interface, with payload modification. */
static void test_outbound_modify(void)
{
    struct ebpfdivert_address addr;
    struct child srv;
    uint32_t len, i;
    char buf[256];
    int ret;
    ebpfdivert_handle_t *h = open_handle("outbound and udp.DstPort == 12348", 0, 0, 0,
                                         "veth_test0");
    if (!h)
        return;
    srv = start_udp_server("ns1", "10.200.1.2", 12348, 2000);
    udp_send("10.200.1.2", 12348, "hello-outbound", 14);
    ret = ebpfdivert_recv(h, pkt, sizeof(pkt), &len, &addr, 2000);
    CHECK(ret == 0, "recv: %s", ebpfdivert_strerror(ret));
    CHECK(addr.outbound && !addr.loopback, "direction");
    /* Rewrite the payload; clearing the checksum flags asks for a recompute. */
    for (i = 0; i + 14 <= len; i++)
        if (memcmp(pkt + i, "hello-outbound", 14) == 0)
            memcpy(pkt + i, "HELLO-OUTBOUND", 14);
    addr.ip_checksum = addr.udp_checksum = 0;
    CHECK(ebpfdivert_send(h, pkt, len, NULL, &addr) == 0, "send");
    child_result(&srv, buf, sizeof(buf));
    CHECK(strcmp(buf, "HELLO-OUTBOUND") == 0, "server got '%s'", buf);
    ebpfdivert_close(h);
}

/* A raw, user-built packet without any captured context is routed. */
static void test_send_crafted(void)
{
    static const uint8_t payload[] = "crafted";
    uint8_t p[64] = {0};
    struct ebpfdivert_address addr;
    struct child srv;
    char buf[256];
    uint16_t ulen = (uint16_t)(8 + sizeof(payload) - 1);
    ebpfdivert_handle_t *h = open_handle("false", 0, 0, 0, NULL);
    if (!h)
        return;
    p[0] = 0x45;
    p[2] = 0;
    p[3] = (uint8_t)(20 + ulen);
    p[8] = 64;
    p[9] = 17;
    inet_pton(AF_INET, "10.200.1.1", p + 12);
    inet_pton(AF_INET, "10.200.1.2", p + 16);
    p[20] = 0x30;           /* sport 12345 */
    p[21] = 0x39;
    p[22] = 0x30;           /* dport 12349 */
    p[23] = 0x3D;
    p[24] = (uint8_t)(ulen >> 8);
    p[25] = (uint8_t)ulen;
    memcpy(p + 28, payload, sizeof(payload) - 1);
    memset(&addr, 0, sizeof(addr));
    addr.layer = EBPFDIVERT_LAYER_NETWORK;
    addr.outbound = 1;
    srv = start_udp_server("ns1", "10.200.1.2", 12349, 2000);
    CHECK(ebpfdivert_send(h, p, (uint32_t)(20 + ulen), NULL, &addr) == 0, "send crafted");
    child_result(&srv, buf, sizeof(buf));
    CHECK(strcmp(buf, "crafted") == 0, "server got '%s'", buf);
    ebpfdivert_close(h);
}

/* A filter the kernel cannot express exactly: non-matching packets must
 * still reach their destination without the application seeing them. */
static void test_inexact_filter_autoreinject(void)
{
    struct ebpfdivert_address addr;
    uint32_t len;
    char buf[256];
    int srv, ret;
    ebpfdivert_handle_t *h = open_handle("udp.DstPort == 12350 and udp.PayloadLength > 10", 0, 0,
                                         0, NULL);
    if (!h)
        return;
    srv = udp_bind("127.0.0.1", 12350, 1000);
    udp_send("127.0.0.1", 12350, "short", 5);
    ret = ebpfdivert_recv(h, pkt, sizeof(pkt), &len, &addr, 300);
    CHECK(ret == -EAGAIN, "short packet was returned (%d)", ret);
    CHECK(udp_recv(srv, buf, sizeof(buf)) == 5, "short packet not auto-re-injected");
    udp_send("127.0.0.1", 12350, "a-longer-payload", 16);
    ret = ebpfdivert_recv(h, pkt, sizeof(pkt), &len, &addr, 1000);
    CHECK(ret == 0 && contains(pkt, len, "a-longer-payload"), "long packet not diverted");
    close(srv);
    ebpfdivert_close(h);
}

/* Two handles: the higher priority one sees the packet first, the lower one
 * only after re-injection, flagged as impostor. */
static void test_priority_chaining(void)
{
    struct ebpfdivert_address addr;
    uint32_t len;
    char buf[256];
    int srv, ret;
    ebpfdivert_handle_t *hi = open_handle("udp.DstPort == 12351", 0, 100, 0, NULL);
    ebpfdivert_handle_t *lo = open_handle("udp.DstPort == 12351", 0, 50, 0, NULL);
    if (!hi || !lo)
        return;
    srv = udp_bind("127.0.0.1", 12351, 500);
    udp_send("127.0.0.1", 12351, "chain", 5);
    ret = ebpfdivert_recv(lo, pkt, sizeof(pkt), &len, &addr, 300);
    CHECK(ret == -EAGAIN, "low priority saw the packet first");
    ret = ebpfdivert_recv(hi, pkt, sizeof(pkt), &len, &addr, 1000);
    CHECK(ret == 0 && !addr.impostor, "high priority recv (%d)", ret);
    CHECK(ebpfdivert_send(hi, pkt, len, NULL, &addr) == 0, "high priority send");
    ret = ebpfdivert_recv(lo, pkt, sizeof(pkt), &len, &addr, 1000);
    CHECK(ret == 0 && addr.impostor, "low priority recv after re-injection (%d, imp %u)", ret,
          addr.impostor);
    ret = ebpfdivert_recv(hi, pkt, sizeof(pkt), &len, &addr, 200);
    CHECK(ret == -EAGAIN, "high priority saw its own injection");
    CHECK(ebpfdivert_send(lo, pkt, len, NULL, &addr) == 0, "low priority send");
    CHECK(udp_recv(srv, buf, sizeof(buf)) == 5, "packet did not reach the socket");
    close(srv);
    ebpfdivert_close(lo);
    ebpfdivert_close(hi);
}

/* Priority 0 handles chain in open order. */
static void test_auto_priority(void)
{
    struct ebpfdivert_address addr;
    uint32_t len;
    int ret;
    ebpfdivert_handle_t *first = open_handle("udp.DstPort == 12352", 0, 0, 0, NULL);
    ebpfdivert_handle_t *second = open_handle("udp.DstPort == 12352", 0, 0, 0, NULL);
    if (!first || !second)
        return;
    udp_send("127.0.0.1", 12352, "auto", 4);
    ret = ebpfdivert_recv(second, pkt, sizeof(pkt), &len, &addr, 300);
    CHECK(ret == -EAGAIN, "second auto-priority handle ran first");
    ret = ebpfdivert_recv(first, pkt, sizeof(pkt), &len, &addr, 1000);
    CHECK(ret == 0, "first auto-priority handle recv (%d)", ret);
    ebpfdivert_close(second);
    ebpfdivert_close(first);
}

static void test_sniff_and_drop(void)
{
    struct ebpfdivert_address addr;
    uint32_t len;
    char buf[256];
    int srv, ret;
    ebpfdivert_handle_t *h = open_handle("udp.DstPort == 12353", 0, 0, EBPFDIVERT_FLAG_SNIFF, NULL);
    if (!h)
        return;
    srv = udp_bind("127.0.0.1", 12353, 1000);
    udp_send("127.0.0.1", 12353, "sniffed", 7);
    CHECK(udp_recv(srv, buf, sizeof(buf)) == 7, "sniffed packet was blocked");
    ret = ebpfdivert_recv(h, pkt, sizeof(pkt), &len, &addr, 1000);
    CHECK(ret == 0 && addr.sniffed, "sniff recv (%d)", ret);
    ebpfdivert_close(h);

    h = open_handle("udp.DstPort == 12353", 0, 0, EBPFDIVERT_FLAG_DROP, NULL);
    if (!h)
        return;
    udp_send("127.0.0.1", 12353, "dropped", 7);
    CHECK(udp_recv(srv, buf, sizeof(buf)) < 0, "dropped packet was delivered");
    ebpfdivert_close(h);
    close(srv);
}

static void test_params_queue_shutdown(void)
{
    struct ebpfdivert_address addr;
    uint64_t v = 0, stats[STAT_MAX];
    uint32_t len;
    int i, got = 0, ret;
    ebpfdivert_handle_t *h = open_handle("udp.DstPort == 12354", 0, 0, 0, NULL);
    if (!h)
        return;
    CHECK(ebpfdivert_get_param(h, EBPFDIVERT_PARAM_QUEUE_LENGTH, &v) == 0 &&
          v == EBPFDIVERT_PARAM_QUEUE_LENGTH_DEFAULT, "default queue length %lu", (unsigned long)v);
    CHECK(ebpfdivert_set_param(h, EBPFDIVERT_PARAM_QUEUE_LENGTH, 1) == -EINVAL, "range check");
    CHECK(ebpfdivert_set_param(h, EBPFDIVERT_PARAM_QUEUE_LENGTH, 32) == 0, "set queue length");
    CHECK(ebpfdivert_get_param(h, EBPFDIVERT_PARAM_VERSION_MAJOR, &v) == 0 && v == 2, "version");
    for (i = 0; i < 100; i++)
        udp_send("127.0.0.1", 12354, "flood", 5);
    usleep(200000);
    while (ebpfdivert_recv(h, pkt, sizeof(pkt), &len, &addr, 100) == 0)
        got++;
    CHECK(got == 32, "queue kept %d packets, expected 32", got);
    ebpfdivert_get_handle_stats(h, stats, STAT_MAX);
    CHECK(stats[STAT_QUEUE_FULL] >= 68, "queue drops %lu", (unsigned long)stats[STAT_QUEUE_FULL]);

    udp_send("127.0.0.1", 12354, "last", 4);
    usleep(100000);
    ebpfdivert_recv(h, NULL, 0, NULL, NULL, 0);     /* pull it into the queue */
    udp_send("127.0.0.1", 12354, "queued", 6);
    usleep(100000);
    CHECK(ebpfdivert_shutdown(h, EBPFDIVERT_SHUTDOWN_RECV) == 0, "shutdown");
    ret = ebpfdivert_recv(h, pkt, sizeof(pkt), &len, &addr, 100);
    CHECK(ret == -ESHUTDOWN || ret == 0, "recv after shutdown (%d)", ret);
    while (ret == 0)
        ret = ebpfdivert_recv(h, pkt, sizeof(pkt), &len, &addr, 100);
    CHECK(ret == -ESHUTDOWN, "recv after drain (%d)", ret);
    CHECK(ebpfdivert_shutdown(h, EBPFDIVERT_SHUTDOWN_SEND) == 0 &&
          ebpfdivert_send(h, pkt, 20, NULL, &addr) == -ESHUTDOWN, "send after shutdown");
    ebpfdivert_close(h);
}

/* Bulk TCP with offloads on: GSO/GRO skbs larger than the MTU must be
 * captured whole and re-injected intact, in both directions. */
struct tcp_sink_arg {
    const char *ip;
    uint16_t port;
    int send;           /* 1: connect back and send, 0: accept and receive */
    int ready_fd;
};

#define BULK_BYTES (1 << 20)

static uint32_t bulk_sum(const uint8_t *p, size_t n, uint32_t sum)
{
    size_t i;
    for (i = 0; i < n; i++)
        sum = sum * 31 + p[i];
    return sum;
}

static void bulk_fill(uint8_t *p, size_t n, size_t off)
{
    size_t i;
    for (i = 0; i < n; i++)
        p[i] = (uint8_t)((off + i) * 7 + ((off + i) >> 11));
}

static void tcp_bulk_child(int wfd, void *a)
{
    struct tcp_sink_arg *arg = a;
    struct sockaddr_in sa = {.sin_family = AF_INET, .sin_port = htons(arg->port)};
    uint8_t buf[65536];
    size_t total = 0;
    uint32_t sum = 0;
    int one = 1, fd = socket(AF_INET, SOCK_STREAM, 0), c;
    char out[64], ok = 1;
    ssize_t n;
    inet_pton(AF_INET, arg->ip, &sa.sin_addr);
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) != 0 || listen(fd, 1) != 0)
        _exit(1);
    if (write(arg->ready_fd, &ok, 1) != 1)
        _exit(1);
    c = accept(fd, NULL, NULL);
    if (arg->send) {
        while (total < BULK_BYTES) {
            size_t chunk = BULK_BYTES - total < sizeof(buf) ? BULK_BYTES - total : sizeof(buf);
            bulk_fill(buf, chunk, total);
            n = write(c, buf, chunk);
            if (n <= 0)
                break;
            sum = bulk_sum(buf, (size_t)n, sum);
            total += (size_t)n;
        }
        shutdown(c, SHUT_WR);
        n = read(c, buf, sizeof(buf));
    } else {
        while ((n = read(c, buf, sizeof(buf))) > 0) {
            sum = bulk_sum(buf, (size_t)n, sum);
            total += (size_t)n;
        }
    }
    snprintf(out, sizeof(out), "%zu %u", total, sum);
    if (write(wfd, out, strlen(out)) < 0)
        _exit(1);
    close(c);
}

static void run_bulk(int child_sends, uint16_t port)
{
    struct tcp_sink_arg arg = {"10.200.1.2", port, child_sends, -1};
    struct sockaddr_in sa = {.sin_family = AF_INET, .sin_port = htons(port)};
    char filter[128], result[64], expect[64];
    struct reinjector r;
    struct child ch;
    static uint8_t buf[65536];
    size_t total = 0;
    uint32_t sum = 0;
    int ready[2], fd;
    char c;
    ssize_t n;
    ebpfdivert_handle_t *h;

    snprintf(filter, sizeof(filter), "tcp.DstPort == %u or tcp.SrcPort == %u", port, port);
    h = open_handle(filter, 0, 0, 0, "veth_test0");
    if (!h)
        return;
    reinjector_start(&r, h);
    if (pipe(ready) != 0)
        return;
    arg.ready_fd = ready[1];
    ch = spawn_in_ns("ns1", tcp_bulk_child, &arg);
    close(ready[1]);
    if (read(ready[0], &c, 1) != 1)
        fprintf(stderr, "bulk child failed\n");
    close(ready[0]);

    inet_pton(AF_INET, "10.200.1.2", &sa.sin_addr);
    fd = tcp_socket();
    CHECK(connect(fd, (struct sockaddr *)&sa, sizeof(sa)) == 0, "connect: %s", strerror(errno));
    if (child_sends) {
        while ((n = read(fd, buf, sizeof(buf))) > 0) {
            sum = bulk_sum(buf, (size_t)n, sum);
            total += (size_t)n;
        }
        close(fd);
    } else {
        while (total < BULK_BYTES) {
            size_t chunk = BULK_BYTES - total < sizeof(buf) ? BULK_BYTES - total : sizeof(buf);
            bulk_fill(buf, chunk, total);
            n = write(fd, buf, chunk);
            if (n <= 0)
                break;
            sum = bulk_sum(buf, (size_t)n, sum);
            total += (size_t)n;
        }
        close(fd);
    }
    child_result(&ch, result, sizeof(result));
    reinjector_stop(&r);
    snprintf(expect, sizeof(expect), "%zu %u", total, sum);
    CHECK(total == BULK_BYTES && strcmp(result, expect) == 0,
          "%s transfer corrupted: ours '%s', peer '%s'", child_sends ? "inbound" : "outbound",
          expect, result);
    printf("  %s bulk: %d packets diverted, largest %u bytes\n",
           child_sends ? "inbound" : "outbound", r.count, r.max_len);
    ebpfdivert_close(h);
}

static void test_bulk_tcp(void)
{
    run_bulk(0, 12355);     /* we send: TSO/GSO on egress */
    run_bulk(1, 12356);     /* peer sends: GRO on ingress */
}

/* NETWORK_FORWARD: traffic routed between ns1 and ns2 through the root. */
static void test_forward_layer(void)
{
    struct udp_sender_arg sarg = {"10.200.2.2", 12357, "forwarded"};
    struct ebpfdivert_address addr;
    struct child srv, sender;
    uint32_t len;
    char buf[256];
    int ret;
    ebpfdivert_handle_t *local = open_handle("udp.DstPort == 12357", EBPFDIVERT_LAYER_NETWORK, 0,
                                             EBPFDIVERT_FLAG_SNIFF, NULL);
    ebpfdivert_handle_t *h = open_handle("udp.DstPort == 12357",
                                         EBPFDIVERT_LAYER_NETWORK_FORWARD, 0, 0, NULL);
    if (!h || !local)
        return;
    srv = start_udp_server("ns2", "10.200.2.2", 12357, 2000);
    sender = spawn_in_ns("ns1", udp_sender_child, &sarg);
    ret = ebpfdivert_recv(h, pkt, sizeof(pkt), &len, &addr, 2000);
    CHECK(ret == 0, "forward recv: %s", ebpfdivert_strerror(ret));
    CHECK(addr.layer == EBPFDIVERT_LAYER_NETWORK_FORWARD && addr.network.if_idx ==
          if_nametoindex("veth_test2"), "layer %u if_idx %u", addr.layer, addr.network.if_idx);
    CHECK(ebpfdivert_send(h, pkt, len, NULL, &addr) == 0, "forward send");
    child_result(&srv, buf, sizeof(buf));
    CHECK(strcmp(buf, "forwarded") == 0, "ns2 got '%s'", buf);
    ret = ebpfdivert_recv(local, pkt, sizeof(pkt), &len, &addr, 200);
    CHECK(ret == -EAGAIN, "NETWORK layer saw a forwarded packet");
    child_result(&sender, buf, sizeof(buf));
    ebpfdivert_close(h);
    ebpfdivert_close(local);
}

static void crash_child(int wfd, void *a)
{
    (void)a;
    ebpfdivert_handle_t *h = ebpfdivert_open("udp.DstPort == 12358", 0, 0, 0, NULL);
    char c = h ? 1 : 0;
    if (write(wfd, &c, 1) != 1)
        _exit(1);
    pause();        /* killed by the parent */
}

/* A process killed with SIGKILL must not leave a classifier stealing traffic. */
static void test_crash_cleanup(void)
{
    struct child ch = spawn_in_ns(NULL, crash_child, NULL);
    char c = 0, buf[256];
    int srv;
    if (read(ch.rfd, &c, 1) != 1 || !c) {
        CHECK(0, "child could not open a handle");
        return;
    }
    kill(ch.pid, SIGKILL);
    waitpid(ch.pid, NULL, 0);
    close(ch.rfd);
    srv = udp_bind("127.0.0.1", 12358, 1000);
    /* Without any cleanup, the orphaned filter goes inert once the owner's
     * heartbeat expires. */
    sleep(4);
    udp_send("127.0.0.1", 12358, "after-crash", 11);
    CHECK(udp_recv(srv, buf, sizeof(buf)) == 11, "traffic still stolen after the owner died");
    /* The reaper then removes it. */
    ebpfdivert_unregister();
    udp_send("127.0.0.1", 12358, "after-reap", 10);
    CHECK(udp_recv(srv, buf, sizeof(buf)) == 10, "traffic blocked after unregister");
    close(srv);
}

static void test_ipv6_loopback(void)
{
    struct ebpfdivert_address addr;
    uint32_t len;
    char buf[256];
    int srv, ret;
    ebpfdivert_handle_t *h = open_handle("ipv6 and udp.DstPort == 12359", 0, 0, 0, NULL);
    if (!h)
        return;
    srv = udp_bind("::1", 12359, 1000);
    udp_send("::1", 12359, "hello-v6", 8);
    ret = ebpfdivert_recv(h, pkt, sizeof(pkt), &len, &addr, 1000);
    CHECK(ret == 0 && addr.ipv6 && addr.loopback, "v6 recv (%d)", ret);
    CHECK(ebpfdivert_send(h, pkt, len, NULL, &addr) == 0, "v6 send");
    CHECK(udp_recv(srv, buf, sizeof(buf)) == 8, "v6 packet not delivered");
    close(srv);
    ebpfdivert_close(h);
}

static void test_event_fd(void)
{
    struct pollfd pfd;
    ebpfdivert_handle_t *h = open_handle("udp.DstPort == 12360", 0, 0, 0, NULL);
    if (!h)
        return;
    pfd.fd = ebpfdivert_get_event_fd(h);
    pfd.events = POLLIN;
    CHECK(poll(&pfd, 1, 100) == 0, "event fd readable while idle");
    udp_send("127.0.0.1", 12360, "poll", 4);
    CHECK(poll(&pfd, 1, 1000) == 1, "event fd not readable with a pending packet");
    CHECK(ebpfdivert_recv(h, pkt, sizeof(pkt), NULL, NULL, 0) == 0, "non-blocking recv");
    ebpfdivert_close(h);
}

static void test_bad_arguments(void)
{
    const char *err_str = NULL;
    uint32_t pos = 0;
    CHECK(ebpfdivert_open("tcp and (", 0, 0, 0, NULL) == NULL && errno == EINVAL, "bad filter");
    CHECK(ebpfdivert_helper_compile_filter("tcp and (", 0, &err_str, &pos) == -EINVAL &&
          err_str != NULL && pos == 9, "error position %u", pos);
    CHECK(ebpfdivert_open("true", 0, 31000, 0, NULL) == NULL && errno == EINVAL, "priority");
    CHECK(ebpfdivert_open("true", 0, 0, EBPFDIVERT_FLAG_SNIFF | EBPFDIVERT_FLAG_DROP, NULL) ==
          NULL && errno == EINVAL, "sniff+drop");
    {
        const char *ifs[] = {"no-such-if0", NULL};
        struct ebpfdivert_open_opts o = {.sz = sizeof(o), .ifnames = ifs};
        CHECK(ebpfdivert_open("true", 0, 0, 0, &o) == NULL && errno == ENODEV, "unknown iface");
    }
}

struct blocked_recv {
    ebpfdivert_handle_t *h;
    int ret;
};

static void *blocked_recv_thread(void *a)
{
    struct blocked_recv *b = a;
    static uint8_t buf[2048];
    b->ret = ebpfdivert_recv(b->h, buf, sizeof(buf), NULL, NULL, -1);
    return NULL;
}

/* close() from another thread wakes a blocked recv and waits for it. */
static void test_close_while_receiving(void)
{
    struct blocked_recv b = {0, 1};
    pthread_t t;
    b.h = open_handle("udp.DstPort == 12361", 0, 0, 0, NULL);
    if (!b.h)
        return;
    pthread_create(&t, NULL, blocked_recv_thread, &b);
    usleep(200000);
    CHECK(ebpfdivert_close(b.h) == 0, "close");
    pthread_join(t, NULL);
    CHECK(b.ret == -ESHUTDOWN, "blocked recv returned %d", b.ret);
}

/****************************************************************************/
/* Event layers                                                             */
/****************************************************************************/

#define EV_FLAGS_SNIFF (EBPFDIVERT_FLAG_SNIFF | EBPFDIVERT_FLAG_RECV_ONLY)

/* Collect events for up to `ms` or until `want` events arrived. */
static int collect(ebpfdivert_handle_t *h, struct ebpfdivert_address *out, int max, int want, int ms)
{
    int n = 0;
    int64_t end;
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    end = ts.tv_sec * 1000LL + ts.tv_nsec / 1000000 + ms;
    while (n < max && n < want) {
        uint32_t len;
        int64_t now;
        clock_gettime(CLOCK_MONOTONIC, &ts);
        now = ts.tv_sec * 1000LL + ts.tv_nsec / 1000000;
        if (now >= end)
            break;
        if (ebpfdivert_recv(h, pkt, sizeof(pkt), &len, &out[n], (int)(end - now)) == 0)
            n++;
    }
    return n;
}

static int has_event(const struct ebpfdivert_address *a, int n, int event)
{
    int i;
    for (i = 0; i < n; i++)
        if (a[i].event == event)
            return 1;
    return 0;
}

static int tcp_listen(uint16_t port)
{
    struct sockaddr_in sa = {.sin_family = AF_INET, .sin_port = htons(port)};
    int one = 1, fd = socket(AF_INET, SOCK_STREAM, 0);
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) != 0 || listen(fd, 4) != 0) {
        close(fd);
        return -1;
    }
    return fd;
}

static int tcp_connect(uint16_t port)
{
    struct sockaddr_in sa = {.sin_family = AF_INET, .sin_port = htons(port)};
    int fd = tcp_socket();
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (connect(fd, (struct sockaddr *)&sa, sizeof(sa)) != 0) {
        int err = errno;
        close(fd);
        errno = err;
        return -1;
    }
    return fd;
}

static void test_layer_flags(void)
{
    CHECK(ebpfdivert_open("true", EBPFDIVERT_LAYER_FLOW, 0, EBPFDIVERT_FLAG_RECV_ONLY, NULL) == NULL &&
          errno == EINVAL, "FLOW without SNIFF");
    CHECK(ebpfdivert_open("true", EBPFDIVERT_LAYER_SOCKET, 0, 0, NULL) == NULL && errno == EINVAL,
          "SOCKET without RECV_ONLY");
    CHECK(ebpfdivert_open("true", EBPFDIVERT_LAYER_REFLECT, 0, EBPFDIVERT_FLAG_SNIFF, NULL) == NULL &&
          errno == EINVAL, "REFLECT without RECV_ONLY");
    /* LISTEN/ACCEPT cannot be refused on Linux. */
    CHECK(ebpfdivert_open("localPort == 1", EBPFDIVERT_LAYER_SOCKET, 0, EBPFDIVERT_FLAG_RECV_ONLY, NULL) ==
          NULL && errno == EOPNOTSUPP, "blocking filter matching LISTEN");
}

static void test_socket_connect_sniff(void)
{
    struct ebpfdivert_address a[8];
    int lfd, cfd, n;
    ebpfdivert_handle_t *h = open_handle("event == CONNECT and remotePort == 12370", EBPFDIVERT_LAYER_SOCKET,
                                         0, EV_FLAGS_SNIFF, NULL);
    if (!h)
        return;
    lfd = tcp_listen(12370);
    cfd = tcp_connect(12370);
    CHECK(cfd >= 0, "connect: %s", strerror(errno));
    n = collect(h, a, 8, 1, 2000);
    CHECK(n == 1, "%d events", n);
    if (n == 1) {
        CHECK(a[0].layer == EBPFDIVERT_LAYER_SOCKET && a[0].event == EBPFDIVERT_EVENT_SOCKET_CONNECT,
              "layer %u event %u", a[0].layer, a[0].event);
        CHECK(a[0].socket.remote_port == 12370 && a[0].socket.protocol == 6, "port %u proto %u",
              a[0].socket.remote_port, a[0].socket.protocol);
        CHECK(a[0].socket.remote_addr[0] == 0x7F000001 && a[0].socket.remote_addr[1] == 0xFFFF,
              "addr %08x %08x", a[0].socket.remote_addr[0], a[0].socket.remote_addr[1]);
        CHECK(a[0].socket.process_id == (uint32_t)getpid(), "pid %u", a[0].socket.process_id);
        CHECK(a[0].loopback && a[0].sniffed && a[0].socket.endpoint_id != 0, "flags");
    }
    close(cfd);
    close(lfd);
    ebpfdivert_close(h);
}

static void test_socket_block_connect(void)
{
    struct ebpfdivert_address a[4];
    int lfd, lfd2, cfd, n;
    ebpfdivert_handle_t *h = open_handle("event == CONNECT and remotePort == 12371", EBPFDIVERT_LAYER_SOCKET,
                                         0, EBPFDIVERT_FLAG_RECV_ONLY, NULL);
    if (!h)
        return;
    lfd = tcp_listen(12371);
    lfd2 = tcp_listen(12376);
    cfd = tcp_connect(12371);
    CHECK(cfd < 0 && errno == EPERM, "blocked connect returned %d (%s)", cfd, strerror(errno));
    n = collect(h, a, 4, 1, 1000);
    CHECK(n == 1 && a[0].event == EBPFDIVERT_EVENT_SOCKET_CONNECT, "blocked event reported (%d)", n);
    cfd = tcp_connect(12376);
    CHECK(cfd >= 0, "unrelated connect: %s", strerror(errno));
    if (cfd >= 0)
        close(cfd);
    close(lfd);
    close(lfd2);
    ebpfdivert_close(h);
    lfd = tcp_listen(12371);
    cfd = tcp_connect(12371);
    CHECK(cfd >= 0, "connect after close: %s", strerror(errno));
    if (cfd >= 0)
        close(cfd);
    close(lfd);
}

static void test_socket_lifecycle(void)
{
    struct ebpfdivert_address a[16];
    int lfd, cfd, afd, n;
    ebpfdivert_handle_t *h = open_handle("localPort == 12372 or remotePort == 12372", EBPFDIVERT_LAYER_SOCKET,
                                         0, EV_FLAGS_SNIFF, NULL);
    if (!h)
        return;
    lfd = tcp_listen(12372);
    cfd = tcp_connect(12372);
    afd = accept(lfd, NULL, NULL);
    close(cfd);
    close(afd);
    close(lfd);
    n = collect(h, a, 16, 16, 1500);
    CHECK(has_event(a, n, EBPFDIVERT_EVENT_SOCKET_BIND), "no BIND");
    CHECK(has_event(a, n, EBPFDIVERT_EVENT_SOCKET_LISTEN), "no LISTEN");
    CHECK(has_event(a, n, EBPFDIVERT_EVENT_SOCKET_CONNECT), "no CONNECT");
    CHECK(has_event(a, n, EBPFDIVERT_EVENT_SOCKET_ACCEPT), "no ACCEPT");
    CHECK(has_event(a, n, EBPFDIVERT_EVENT_SOCKET_CLOSE), "no CLOSE");
    ebpfdivert_close(h);
}

static void test_flow_layer(void)
{
    struct ebpfdivert_address a[16];
    int lfd, cfd, afd, n, i, udp_est = 0, udp_del = 0;
    ebpfdivert_handle_t *h = open_handle("localPort == 12373 or remotePort == 12373 or "
                                         "localPort == 12374 or remotePort == 12374",
                                         EBPFDIVERT_LAYER_FLOW, 0, EV_FLAGS_SNIFF, NULL);
    if (!h)
        return;
    lfd = tcp_listen(12373);
    cfd = tcp_connect(12373);
    afd = accept(lfd, NULL, NULL);
    close(cfd);
    close(afd);
    close(lfd);
    n = collect(h, a, 16, 4, 2000);
    CHECK(has_event(a, n, EBPFDIVERT_EVENT_FLOW_ESTABLISHED), "no TCP ESTABLISHED");
    CHECK(has_event(a, n, EBPFDIVERT_EVENT_FLOW_DELETED), "no TCP DELETED");
    for (i = 0; i < n; i++)
        CHECK(a[i].layer == EBPFDIVERT_LAYER_FLOW && a[i].flow.protocol == 6, "flow %d", i);

    {
        int srv = udp_bind("127.0.0.1", 12374, 500);
        char buf[64];
        int c = socket(AF_INET, SOCK_DGRAM, 0);
        struct sockaddr_in sa = {.sin_family = AF_INET, .sin_port = htons(12374)};
        sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        sendto(c, "u1", 2, 0, (struct sockaddr *)&sa, sizeof(sa));
        sendto(c, "u2", 2, 0, (struct sockaddr *)&sa, sizeof(sa));
        udp_recv(srv, buf, sizeof(buf));
        close(c);
        close(srv);
    }
    n = collect(h, a, 16, 16, 1500);
    for (i = 0; i < n; i++) {
        if (a[i].flow.protocol != 17)
            continue;
        udp_est += a[i].event == EBPFDIVERT_EVENT_FLOW_ESTABLISHED;
        udp_del += a[i].event == EBPFDIVERT_EVENT_FLOW_DELETED;
    }
    /* One flow per socket: client -> server (egress) and server <- client (ingress). */
    CHECK(udp_est == 2, "UDP established %d", udp_est);
    CHECK(udp_del == 2, "UDP deleted %d", udp_del);
    ebpfdivert_close(h);
}

static void test_reflect_layer(void)
{
    struct ebpfdivert_address a[16];
    int n, i, opened = 0, closed = 0;
    ebpfdivert_handle_t *r = open_handle("true", EBPFDIVERT_LAYER_REFLECT, 0, EV_FLAGS_SNIFF, NULL);
    ebpfdivert_handle_t *h;
    if (!r)
        return;
    collect(r, a, 16, 16, 300);     /* existing handles, including r itself */
    h = open_handle("udp.DstPort == 12375", 0, 1234, 0, NULL);
    if (!h)
        return;
    n = collect(r, a, 16, 1, 1000);
    for (i = 0; i < n; i++) {
        if (a[i].event == EBPFDIVERT_EVENT_REFLECT_OPEN && a[i].reflect.priority == 1234) {
            opened++;
            CHECK(a[i].reflect.process_id == (uint32_t)getpid() && a[i].reflect.layer == 0,
                  "reflect data pid %u layer %u", a[i].reflect.process_id, a[i].reflect.layer);
            CHECK(strncmp((const char *)pkt, "@WinDiv_", 8) == 0 || n > 1, "filter object");
        }
    }
    CHECK(opened == 1, "OPEN events %d", opened);
    ebpfdivert_close(h);
    n = collect(r, a, 16, 1, 1000);
    for (i = 0; i < n; i++)
        closed += a[i].event == EBPFDIVERT_EVENT_REFLECT_CLOSE && a[i].reflect.priority == 1234;
    CHECK(closed == 1, "CLOSE events %d", closed);
    ebpfdivert_close(r);
}

struct test_case {
    const char *name;
    void (*fn)(void);
};

static const struct test_case cases[] = {
    {"bad arguments", test_bad_arguments},
    {"loopback single sighting", test_loopback_single_sighting},
    {"tcp.Port both directions", test_tcp_port_both_directions},
    {"inbound veth + redirect", test_inbound_veth},
    {"outbound veth + modify", test_outbound_modify},
    {"crafted packet", test_send_crafted},
    {"inexact filter auto re-inject", test_inexact_filter_autoreinject},
    {"priority chaining", test_priority_chaining},
    {"auto priority", test_auto_priority},
    {"sniff and drop", test_sniff_and_drop},
    {"params, queue, shutdown", test_params_queue_shutdown},
    {"IPv6 loopback", test_ipv6_loopback},
    {"event fd", test_event_fd},
    {"bulk TCP with offloads", test_bulk_tcp},
    {"forward layer", test_forward_layer},
    {"close while receiving", test_close_while_receiving},
    {"event layer flags", test_layer_flags},
    {"SOCKET connect (sniff)", test_socket_connect_sniff},
    {"SOCKET connect (block)", test_socket_block_connect},
    {"SOCKET lifecycle", test_socket_lifecycle},
    {"FLOW layer", test_flow_layer},
    {"REFLECT layer", test_reflect_layer},
    {"crash cleanup", test_crash_cleanup},
};

int main(int argc, char **argv)
{
    size_t i;
    const char *only = argc > 1 ? argv[1] : NULL;
    signal(SIGPIPE, SIG_IGN);
    for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        int before = failures;
        if (only && !strstr(cases[i].name, only))
            continue;
        printf("[TEST] %s\n", cases[i].name);
        cases[i].fn();
        printf("  -> %s\n", failures == before ? "ok" : "FAILED");
    }
    printf("%d checks passed, %d failed\n", passes, failures);
    return failures ? 1 : 0;
}
