// SPDX-License-Identifier: GPL-2.0-or-later OR LGPL-3.0-or-later
/*
 * handle.c - the WinDivert-compatible handle API of libebpfdivert.
 *
 * Every handle loads its own instance of the embedded BPF object, attaches
 * the TC programs to the requested interfaces (cls_bpf on clsact) at a TC
 * priority derived from the WinDivert priority,
 * and consumes the ring buffer into a bounded user-space queue.  Filters are
 * compiled by the vendored WinDivert compiler; the kernel runs a lowered
 * superset (prefilter.c) and packets it lets through that do not match the
 * exact filter are re-injected here.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <net/if.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/file.h>
#include <sys/ioctl.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/timerfd.h>
#include <time.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <linux/if_arp.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/virtio_net.h>
#include <netinet/in.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "ebpfdivert.h"
#include "internal.h"
#include "prefilter.h"
#include "wd.h"

#ifndef SO_MARK
#define SO_MARK 36
#endif

#define DEFAULT_RING_BYTES   (8u << 20)
#define AUTO_PRIORITY_BASE   30001u
#define REGISTRY_DIR         "/sys/fs/bpf/ebpfdivert"
#define REGISTRY_PIN         REGISTRY_DIR "/registry"
#define REGISTRY_LOCK        "/run/ebpfdivert.lock"
#define REGISTRY_MAX         1024
#define REG_MAX_ATTACH       128
#define REG_FILTER_MAX       4096
#define MTU_CACHE            16
#define HEARTBEAT_PERIOD_MS  500
#define HEARTBEAT_TIMEOUT_NS (3ULL * 1000000000ULL)
#define EVENT_RING_BYTES     (1u << 20)
#define REFLECT_PERIOD_MS    100
#define UDP_TRACK_MAX        65536
#define EBD_MAX_LINKS            16

/* Opaque L2 data stashed in the unused part of the address union so that a
 * received packet can be re-injected exactly where it was captured. */
#define L2_STASH_OFFSET      16
#define L2_STASH_MAGIC       0xEB
#define L2_STASH_MAX         22

struct l2_stash {
    uint8_t magic;
    uint8_t len;
    uint16_t gso_size;
    uint8_t data[L2_STASH_MAX];
} __attribute__((packed));

_Static_assert(sizeof(struct ebpfdivert_address) == 80, "address size");
_Static_assert(offsetof(struct ebpfdivert_address, reserved3) == 16, "address union");
_Static_assert(offsetof(struct ebpfdivert_data_flow, protocol) == 56, "flow layout");
_Static_assert(offsetof(struct ebpfdivert_data_reflect, priority) == 24, "reflect layout");
_Static_assert(L2_STASH_OFFSET + sizeof(struct l2_stash) <= 64, "l2 stash");

/****************************************************************************/
/* Registry of live handles (shared by all processes through bpffs)        */
/****************************************************************************/

struct reg_attach {
    uint32_t ifindex;
    uint32_t attach_point;      /* BPF_TC_INGRESS / BPF_TC_EGRESS */
    uint32_t handle;
    uint32_t priority;
};

struct reg_entry {
    uint32_t pid;
    uint32_t tc_prio;
    uint64_t pid_start;         /* /proc/<pid>/stat starttime */
    int64_t timestamp;
    uint64_t flags;
    uint32_t layer;
    int16_t priority;
    uint16_t legacy;            /* attachments are legacy cls_bpf */
    uint32_t nattach;
    uint32_t filter_len;
    struct reg_attach attach[REG_MAX_ATTACH];
    char filter[REG_FILTER_MAX];
};

/****************************************************************************/
/* Handle                                                                   */
/****************************************************************************/

struct qentry {
    struct qentry *next;
    struct ebpfdivert_address addr;
    uint32_t len;
    uint8_t data[];
};

/* A handle a REFLECT handle has reported as open. */
struct reflect_seen {
    uint64_t id;
    struct ebpfdivert_data_reflect data;
    uint32_t filter_len;
    char *filter;
};

struct inject_sock {
    uint32_t mark;
    int fd;
};

struct attachment {
    int ifindex;
    int ingress;
    struct bpf_tc_hook hook;
    struct bpf_tc_opts opts;
    int legacy;
};

struct ebpfdivert_handle {
    int layer;
    uint64_t flags;
    int16_t priority;
    uint32_t tc_prio;
    uint64_t reg_id;

    struct wd_filter *filter;
    int exact;

    struct bpf_object *obj;
    struct ring_buffer *rb;
    int cfg_fd;
    int stats_fd;
    pthread_mutex_t cfg_lock;
    struct divert_config cfg;
    struct ebpfdivert_handle *hb_next;  /* heartbeat list */

    struct attachment *att;
    int natt;

    /* FLOW / SOCKET */
    struct bpf_link *links[EBD_MAX_LINKS];
    int nlinks;
    struct event_config evcfg;
    struct divert_event *udp;       /* UDP flows reported as established */
    unsigned nudp;

    /* REFLECT */
    int timer_fd;
    struct reflect_seen *seen;
    unsigned nseen;

    /* Calls in progress; close waits for them before freeing. */
    pthread_mutex_t rlock;
    pthread_cond_t rcond;
    int inflight;
    int closing;

    /* Receive side. */
    pthread_mutex_t qlock;
    pthread_mutex_t poll_lock;
    struct qentry *qhead, *qtail;
    uint64_t qlen, qbytes;
    uint64_t queue_length, queue_time, queue_size;
    uint64_t queue_drops;
    int shut_recv, shut_send;
    int epfd;                   /* ring epoll fd + wake_fd */
    int wake_fd;                /* eventfd: queue non-empty or shut down */
    int wake_set;

    /* Send side. */
    pthread_mutex_t slock;
    struct inject_sock *socks;
    int nsocks;
    int raw4, raw6;
    int lo_ifindex;
    struct {
        int ifindex;
        int mtu;
        int64_t stamp;
    } mtu_cache[MTU_CACHE];
};

static int64_t now_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int64_t)ts.tv_sec * 1000000000LL + ts.tv_nsec;
}

static int handle_enter(struct ebpfdivert_handle *h)
{
    pthread_mutex_lock(&h->rlock);
    if (h->closing) {
        pthread_mutex_unlock(&h->rlock);
        return -EBADF;
    }
    h->inflight++;
    pthread_mutex_unlock(&h->rlock);
    return 0;
}

static void handle_leave(struct ebpfdivert_handle *h)
{
    pthread_mutex_lock(&h->rlock);
    if (--h->inflight == 0 && h->closing)
        pthread_cond_broadcast(&h->rcond);
    pthread_mutex_unlock(&h->rlock);
}

/* Wrap a public entry point so that close() never frees a handle in use. */
#define GUARDED(h, expr)                        \
    ({                                          \
        int __ret = handle_enter(h);            \
        if (__ret == 0) {                       \
            __ret = (expr);                     \
            handle_leave(h);                    \
        }                                       \
        __ret;                                  \
    })

/****************************************************************************/
/* Owner heartbeat                                                          */
/****************************************************************************/

/*
 * One thread per process refreshes the heartbeat of every open handle.  The
 * BPF program stops diverting (and dropping) once a handle's heartbeat is
 * older than HEARTBEAT_TIMEOUT_NS, so a process killed without closing its
 * handles cannot keep swallowing traffic; the orphaned filters are then
 * removed by the registry reaper.
 */
static pthread_mutex_t hb_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t hb_cond = PTHREAD_COND_INITIALIZER;
static struct ebpfdivert_handle *hb_list;
static int hb_running;

static int write_config(struct ebpfdivert_handle *h);

static void *heartbeat_main(void *arg)
{
    (void)arg;
    pthread_mutex_lock(&hb_lock);
    for (;;) {
        struct ebpfdivert_handle *h;
        struct timespec ts;
        while (!hb_list)
            pthread_cond_wait(&hb_cond, &hb_lock);
        for (h = hb_list; h; h = h->hb_next)
            write_config(h);
        clock_gettime(CLOCK_REALTIME, &ts);
        ts.tv_nsec += HEARTBEAT_PERIOD_MS * 1000000L;
        if (ts.tv_nsec >= 1000000000L) {
            ts.tv_sec++;
            ts.tv_nsec -= 1000000000L;
        }
        pthread_cond_timedwait(&hb_cond, &hb_lock, &ts);
    }
    return NULL;
}

static void heartbeat_after_fork(void)
{
    /* The thread does not survive fork(); the child starts its own. */
    pthread_mutex_init(&hb_lock, NULL);
    pthread_cond_init(&hb_cond, NULL);
    hb_list = NULL;
    hb_running = 0;
}

static void heartbeat_add(struct ebpfdivert_handle *h)
{
    pthread_mutex_lock(&hb_lock);
    if (!hb_running) {
        pthread_t t;
        pthread_attr_t attr;
        static int atfork_done;
        if (!atfork_done) {
            pthread_atfork(NULL, NULL, heartbeat_after_fork);
            atfork_done = 1;
        }
        pthread_attr_init(&attr);
        pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
        if (pthread_create(&t, &attr, heartbeat_main, NULL) == 0)
            hb_running = 1;
        pthread_attr_destroy(&attr);
    }
    h->hb_next = hb_list;
    hb_list = h;
    pthread_cond_signal(&hb_cond);
    pthread_mutex_unlock(&hb_lock);
}

static void heartbeat_remove(struct ebpfdivert_handle *h)
{
    struct ebpfdivert_handle **pp;
    pthread_mutex_lock(&hb_lock);
    for (pp = &hb_list; *pp; pp = &(*pp)->hb_next) {
        if (*pp == h) {
            *pp = h->hb_next;
            break;
        }
    }
    pthread_mutex_unlock(&hb_lock);
}

/****************************************************************************/
/* Registry helpers                                                         */
/****************************************************************************/

static uint64_t proc_start_time(pid_t pid)
{
    char path[64], buf[1024];
    FILE *f;
    char *p;
    unsigned long long start = 0;
    int i;

    snprintf(path, sizeof(path), "/proc/%d/stat", (int)pid);
    f = fopen(path, "r");
    if (!f)
        return 0;
    if (!fgets(buf, sizeof(buf), f)) {
        fclose(f);
        return 0;
    }
    fclose(f);
    /* Field 22 (starttime); skip "pid (comm)" first, comm may contain spaces. */
    p = strrchr(buf, ')');
    if (!p)
        return 0;
    p++;
    for (i = 0; i < 19 && p; i++)
        p = strchr(p + 1, ' ');
    if (p)
        start = strtoull(p + 1, NULL, 10);
    return start;
}

static int proc_alive(uint32_t pid, uint64_t start)
{
    if (kill((pid_t)pid, 0) != 0 && errno == ESRCH)
        return 0;
    return proc_start_time((pid_t)pid) == start;
}

static int registry_lock(void)
{
    int fd = open(REGISTRY_LOCK, O_RDWR | O_CREAT | O_CLOEXEC, 0600);
    if (fd < 0)
        return -1;
    if (flock(fd, LOCK_EX) != 0) {
        close(fd);
        return -1;
    }
    return fd;
}

static void registry_unlock(int fd)
{
    if (fd >= 0) {
        flock(fd, LOCK_UN);
        close(fd);
    }
}

/* Open (creating and pinning if needed) the registry map; -1 if bpffs is
 * unavailable, in which case handles still work without cross-process
 * features. */
static int registry_open(void)
{
    int fd = bpf_obj_get(REGISTRY_PIN);
    if (fd >= 0)
        return fd;
    mkdir(REGISTRY_DIR, 0700);
    {
        DECLARE_LIBBPF_OPTS(bpf_map_create_opts, mopts, .map_flags = BPF_F_NO_PREALLOC);
        fd = bpf_map_create(BPF_MAP_TYPE_HASH, "ebpfdivert_reg", sizeof(uint64_t),
                            sizeof(struct reg_entry), REGISTRY_MAX, &mopts);
    }
    if (fd < 0)
        return -1;
    if (bpf_obj_pin(fd, REGISTRY_PIN) != 0) {
        close(fd);
        return bpf_obj_get(REGISTRY_PIN);
    }
    return fd;
}

static void detach_legacy_entry(const struct reg_entry *e)
{
    uint32_t i;
    for (i = 0; i < e->nattach && i < REG_MAX_ATTACH; i++) {
        DECLARE_LIBBPF_OPTS(bpf_tc_hook, hook,
            .ifindex = (int)e->attach[i].ifindex,
            .attach_point = (enum bpf_tc_attach_point)e->attach[i].attach_point);
        DECLARE_LIBBPF_OPTS(bpf_tc_opts, opts,
            .handle = e->attach[i].handle,
            .priority = e->attach[i].priority);
        bpf_tc_detach(&hook, &opts);
    }
}

/* Remove entries of dead processes (detaching their legacy filters).
 * Must hold the registry lock. */
static void registry_reap(int reg_fd)
{
    uint64_t key, next, *prev = NULL;
    struct reg_entry *e = malloc(sizeof(*e));
    uint64_t dead[REGISTRY_MAX];
    int ndead = 0, i;

    if (!e)
        return;
    while (bpf_map_get_next_key(reg_fd, prev, &next) == 0) {
        key = next;
        prev = &key;
        if (bpf_map_lookup_elem(reg_fd, &key, e) != 0)
            continue;
        if (!proc_alive(e->pid, e->pid_start)) {
            if (e->legacy)
                detach_legacy_entry(e);
            if (ndead < REGISTRY_MAX)
                dead[ndead++] = key;
        }
    }
    for (i = 0; i < ndead; i++)
        bpf_map_delete_elem(reg_fd, &dead[i]);
    free(e);
}

/* Highest TC priority number in use by any live handle (0 if none). */
static uint32_t registry_max_tc_prio(int reg_fd)
{
    uint64_t key, next, *prev = NULL;
    struct reg_entry *e = malloc(sizeof(*e));
    uint32_t max = 0;
    if (!e)
        return 0;
    while (bpf_map_get_next_key(reg_fd, prev, &next) == 0) {
        key = next;
        prev = &key;
        if (bpf_map_lookup_elem(reg_fd, &key, e) == 0 && e->tc_prio > max)
            max = e->tc_prio;
    }
    free(e);
    return max;
}

/* Process-local fallback when bpffs is not available. */
static uint32_t local_max_tc_prio;
static pthread_mutex_t local_prio_lock = PTHREAD_MUTEX_INITIALIZER;

/****************************************************************************/
/* Loading and attaching                                                    */
/****************************************************************************/

static int read_sysctl_int(const char *path)
{
    char buf[32];
    int fd = open(path, O_RDONLY | O_CLOEXEC), v = 0;
    ssize_t n;
    if (fd < 0)
        return 0;
    n = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (n > 0) {
        buf[n] = '\0';
        v = atoi(buf);
    }
    return v;
}


static int attach_legacy(struct attachment *a, struct bpf_program *prog, uint32_t tc_prio)
{
    int err;
    memset(&a->hook, 0, sizeof(a->hook));
    memset(&a->opts, 0, sizeof(a->opts));
    a->hook.sz = sizeof(a->hook);
    a->hook.ifindex = a->ifindex;
    a->hook.attach_point = a->ingress ? BPF_TC_INGRESS : BPF_TC_EGRESS;
    a->opts.sz = sizeof(a->opts);
    a->opts.prog_fd = bpf_program__fd(prog);
    a->opts.priority = tc_prio;
    err = bpf_tc_hook_create(&a->hook);
    if (err && err != -EEXIST)
        return err;
    err = bpf_tc_attach(&a->hook, &a->opts);
    if (err)
        return err;
    a->legacy = 1;
    /* Keep only what bpf_tc_detach() needs. */
    a->opts.prog_fd = 0;
    a->opts.prog_id = 0;
    a->opts.flags = 0;
    return 0;
}

static void detach_all(struct ebpfdivert_handle *h)
{
    int i;
    for (i = 0; i < h->natt; i++) {
        struct attachment *a = &h->att[i];
        if (a->legacy) {
            bpf_tc_detach(&a->hook, &a->opts);
            a->legacy = 0;
        }
    }
    h->natt = 0;
}

/*
 * Programs are attached as classic cls_bpf filters (clsact), ordered by TC
 * priority.  TCX links are not used: TCX maps TC_ACT_STOLEN to "next", and
 * its only alternative (drop) makes TCP back off on every diverted segment.
 */
static int attach_one(struct ebpfdivert_handle *h, int ifindex, int ingress)
{
    struct bpf_program *prog = bpf_object__find_program_by_name(
        h->obj, ingress ? "tc_divert_ingress" : "tc_divert_egress");
    struct attachment *a = &h->att[h->natt];
    int err;

    if (!prog)
        return -ENOENT;
    memset(a, 0, sizeof(*a));
    a->ifindex = ifindex;
    a->ingress = ingress;
    err = attach_legacy(a, prog, h->tc_prio);
    if (err)
        return err;
    h->natt++;
    return 0;
}

static int iface_selected(const char *const *ifnames, const char *name)
{
    int i;
    if (!ifnames)
        return 1;
    for (i = 0; ifnames[i]; i++)
        if (strcmp(ifnames[i], name) == 0)
            return 1;
    return 0;
}

static int attach_interfaces(struct ebpfdivert_handle *h, const char *const *ifnames)
{
    struct if_nameindex *ifs = if_nameindex(), *it;
    int n = 0, attached = 0, err = 0, lo_selected = 0, i;

    if (!ifs)
        return -errno;
    for (it = ifs; it->if_index; it++)
        n++;
    h->att = calloc((size_t)(2 * n + 2), sizeof(*h->att));
    if (!h->att) {
        if_freenameindex(ifs);
        return -ENOMEM;
    }
    if (ifnames) {
        for (i = 0; ifnames[i]; i++) {
            if (if_nametoindex(ifnames[i]) == 0) {
                if_freenameindex(ifs);
                return -ENODEV;
            }
        }
    }
    for (it = ifs; it->if_index; it++) {
        int is_lo = ((int)it->if_index == h->lo_ifindex);
        int sel = iface_selected(ifnames, it->if_name);
        if (is_lo)
            lo_selected = sel;
        /* lo is always needed: inbound injection is redirected through it. */
        if (!sel && !is_lo)
            continue;
        err = attach_one(h, (int)it->if_index, 1);
        if (!err)
            err = attach_one(h, (int)it->if_index, 0);
        if (err) {
            pr_log(EBPFDIVERT_WARN, "ebpfdivert: attaching to %s failed: %s\n",
                   it->if_name, strerror(-err));
            if (sel && ifnames) {
                if_freenameindex(ifs);
                return err;
            }
            continue;
        }
        if (sel)
            attached++;
    }
    if_freenameindex(ifs);
    if (!lo_selected)
        h->cfg.flags |= CFG_F_SKIP_LO;
    return attached ? 0 : (err ? err : -ENODEV);
}

/****************************************************************************/
/* Receive path                                                             */
/****************************************************************************/

static void wake_update(struct ebpfdivert_handle *h)
{
    /* Must hold qlock.  wake_fd is readable iff there is something to return. */
    int want = (h->qhead != NULL) || h->shut_recv;
    uint64_t v;
    if (want && !h->wake_set) {
        v = 1;
        if (write(h->wake_fd, &v, sizeof(v)) == sizeof(v))
            h->wake_set = 1;
    } else if (!want && h->wake_set) {
        if (read(h->wake_fd, &v, sizeof(v)) == sizeof(v))
            h->wake_set = 0;
    }
}

static void stash_l2(struct ebpfdivert_address *addr, const uint8_t *l2, unsigned len,
                     uint16_t gso_size)
{
    struct l2_stash *s = (struct l2_stash *)(addr->reserved3 + L2_STASH_OFFSET);
    if (len > L2_STASH_MAX)
        return;
    s->magic = L2_STASH_MAGIC;
    s->len = (uint8_t)len;
    s->gso_size = gso_size;
    memcpy(s->data, l2, len);
}

static const struct l2_stash *get_stash(const struct ebpfdivert_address *addr)
{
    const struct l2_stash *s = (const struct l2_stash *)(addr->reserved3 + L2_STASH_OFFSET);
    if (s->magic != L2_STASH_MAGIC || s->len > L2_STASH_MAX)
        return NULL;
    return s;
}

static int inject(struct ebpfdivert_handle *h, const uint8_t *pkt, uint32_t len,
                  const struct ebpfdivert_address *addr, int fix_checksums);

static void queue_push(struct ebpfdivert_handle *h, struct qentry *e)
{
    pthread_mutex_lock(&h->qlock);
    if (h->qlen >= h->queue_length || h->qbytes + e->len > h->queue_size) {
        h->queue_drops++;
        pthread_mutex_unlock(&h->qlock);
        free(e);
        return;
    }
    e->next = NULL;
    if (h->qtail)
        h->qtail->next = e;
    else
        h->qhead = e;
    h->qtail = e;
    h->qlen++;
    h->qbytes += e->len;
    wake_update(h);
    pthread_mutex_unlock(&h->qlock);
}

static int ring_callback(void *ctx, void *data, size_t size)
{
    struct ebpfdivert_handle *h = ctx;
    const struct divert_pkt_header *hdr = data;
    const uint8_t *frame = (const uint8_t *)data + sizeof(*hdr);
    const uint8_t *pkt;
    struct qentry *e;
    uint32_t len;
    int match, sniffed;
    int ip_ok, tcp_ok, udp_ok;

    if (size < sizeof(*hdr) || hdr->cap_len > size - sizeof(*hdr) ||
        hdr->l2_len > hdr->cap_len)
        return 0;
    pkt = frame + hdr->l2_len;
    len = hdr->cap_len - hdr->l2_len;
    sniffed = !!(hdr->flags & PKT_F_SNIFFED);

    e = malloc(sizeof(*e) + len);
    if (!e)
        return 0;
    memset(&e->addr, 0, sizeof(e->addr));
    e->len = len;
    memcpy(e->data, pkt, len);
    e->addr.timestamp = (int64_t)hdr->timestamp;
    e->addr.layer = (uint32_t)h->layer;
    e->addr.event = EBPFDIVERT_EVENT_NETWORK_PACKET;
    e->addr.sniffed = (uint32_t)sniffed;
    e->addr.outbound = (hdr->direction == 2);
    e->addr.loopback = !!(hdr->flags & PKT_F_LOOPBACK);
    e->addr.impostor = !!(hdr->flags & PKT_F_IMPOSTOR);
    e->addr.ipv6 = (len > 0 && (pkt[0] >> 4) == 6);
    e->addr.network.if_idx = hdr->ifindex;
    e->addr.network.sub_if_idx = 0;
    wd_verify_checksums(pkt, len, &ip_ok, &tcp_ok, &udp_ok);
    e->addr.ip_checksum = (uint32_t)ip_ok;
    e->addr.tcp_checksum = (uint32_t)tcp_ok;
    e->addr.udp_checksum = (uint32_t)udp_ok;
    stash_l2(&e->addr, frame, hdr->l2_len, hdr->gso_size);

    /* Exact evaluation when the kernel rules are only a superset. */
    if (!h->exact || (hdr->flags & PKT_F_FRAGMENT)) {
        match = wd_filter_eval(h->filter, e->data, e->len, &e->addr);
        if (match <= 0) {
            if (!sniffed)
                inject(h, e->data, e->len, &e->addr, 1);
            free(e);
            return 0;
        }
        if (h->flags & EBPFDIVERT_FLAG_DROP) {
            free(e);        /* matched: drop */
            return 0;
        }
    }
    queue_push(h, e);
    return 0;
}

static struct qentry *queue_pop(struct ebpfdivert_handle *h)
{
    /* Must hold qlock. */
    struct qentry *e;
    int64_t now = now_ns();
    while ((e = h->qhead) != NULL) {
        h->qhead = e->next;
        if (!h->qhead)
            h->qtail = NULL;
        h->qlen--;
        h->qbytes -= e->len;
        if (now - e->addr.timestamp <= (int64_t)h->queue_time * 1000000LL)
            break;
        /* Expired, like WinDivert's QUEUE_TIME. */
        h->queue_drops++;
        free(e);
    }
    wake_update(h);
    return e;
}

static int consume_ring(struct ebpfdivert_handle *h)
{
    int n;
    if (!h->rb)
        return 0;
    pthread_mutex_lock(&h->poll_lock);
    n = ring_buffer__consume(h->rb);
    pthread_mutex_unlock(&h->poll_lock);
    return n;
}

/* Wait for the next queue entry.  Returns it, or NULL with *err set. */
static void reflect_poll(struct ebpfdivert_handle *h);

static struct qentry *next_entry(struct ebpfdivert_handle *h, int timeout_ms, int *err)
{
    int64_t deadline = timeout_ms > 0 ? now_ns() + (int64_t)timeout_ms * 1000000LL : 0;
    struct epoll_event ev[2];
    struct qentry *e;

    for (;;) {
        int shut;
        if (h->layer == EBPFDIVERT_LAYER_REFLECT)
            reflect_poll(h);
        pthread_mutex_lock(&h->qlock);
        e = queue_pop(h);
        shut = h->shut_recv;
        pthread_mutex_unlock(&h->qlock);
        if (e)
            return e;
        if (shut) {
            /* Packets captured before the shutdown are still delivered. */
            if (consume_ring(h) > 0)
                continue;
            *err = -ESHUTDOWN;
            return NULL;
        }

        if (consume_ring(h) > 0)
            continue;
        pthread_mutex_lock(&h->qlock);
        e = h->qhead;
        pthread_mutex_unlock(&h->qlock);
        if (e)
            continue;

        if (timeout_ms == 0) {
            *err = -EAGAIN;
            return NULL;
        } else {
            int wait = -1, n;
            if (timeout_ms > 0) {
                int64_t left = deadline - now_ns();
                if (left <= 0) {
                    *err = -EAGAIN;
                    return NULL;
                }
                wait = (int)((left + 999999) / 1000000);
            }
            n = epoll_wait(h->epfd, ev, 2, wait);
            if (n < 0 && errno != EINTR) {
                *err = -errno;
                return NULL;
            }
        }
    }
}

static int ebpfdivert_recv_impl(ebpfdivert_handle_t *h, void *pkt, uint32_t pkt_len, uint32_t *recv_len,
                    struct ebpfdivert_address *addr, int timeout_ms)
{
    struct qentry *e;
    int err = 0;

    if (!h)
        return -EINVAL;
    if (h->flags & EBPFDIVERT_FLAG_SEND_ONLY)
        return -EPERM;
    e = next_entry(h, timeout_ms, &err);
    if (!e)
        return err;
    if (recv_len)
        *recv_len = e->len;
    if (addr)
        *addr = e->addr;
    if (pkt) {
        if (e->len > pkt_len) {
            free(e);
            return -ENOBUFS;
        }
        memcpy(pkt, e->data, e->len);
    }
    free(e);
    return 0;
}

static int ebpfdivert_recv_ex_impl(ebpfdivert_handle_t *h, void *pkt, uint32_t pkt_len, uint32_t *recv_len,
                       struct ebpfdivert_address *addrs, uint32_t *addr_len, int timeout_ms)
{
    uint32_t max, count = 0, used = 0;
    int err = 0;

    if (!h || !addr_len || *addr_len == 0)
        return -EINVAL;
    if (h->flags & EBPFDIVERT_FLAG_SEND_ONLY)
        return -EPERM;
    max = *addr_len;
    while (count < max) {
        struct qentry *e;
        if (count > 0) {
            /* Only take what is already there; peek so we never drop. */
            consume_ring(h);
            pthread_mutex_lock(&h->qlock);
            e = h->qhead;
            if (e && pkt && used + e->len > pkt_len)
                e = NULL;
            else if (e)
                e = queue_pop(h);
            pthread_mutex_unlock(&h->qlock);
            if (!e)
                break;
        } else {
            e = next_entry(h, timeout_ms, &err);
            if (!e)
                return err;
            if (pkt && e->len > pkt_len) {
                free(e);
                return -ENOBUFS;
            }
        }
        if (pkt)
            memcpy((uint8_t *)pkt + used, e->data, e->len);
        if (addrs)
            addrs[count] = e->addr;
        used += e->len;
        count++;
        free(e);
    }
    *addr_len = count;
    if (recv_len)
        *recv_len = used;
    return 0;
}

/****************************************************************************/
/* Send path                                                                */
/****************************************************************************/

static uint16_t csum_fold32(uint32_t sum)
{
    while (sum >> 16)
        sum = (sum & 0xFFFF) + (sum >> 16);
    return (uint16_t)sum;
}

static uint32_t csum_add(uint32_t sum, const uint8_t *p, size_t len)
{
    size_t i;
    for (i = 0; i + 1 < len; i += 2)
        sum += (uint32_t)((p[i] << 8) | p[i + 1]);
    if (len & 1)
        sum += (uint32_t)(p[len - 1] << 8);
    return sum;
}

/*
 * Prepare a GSO send: the transport checksum must hold the (uncomplemented)
 * pseudo-header sum, and the virtio header describes the segmentation.
 * Returns 0 if the packet is not a GSO candidate.
 */
static int prepare_gso(uint8_t *pkt, uint32_t len, uint32_t l2_len, uint16_t mtu,
                       uint16_t gso_size, struct virtio_net_hdr *vh)
{
    struct wd_packet_info info;
    uint8_t *ip, *th;
    uint32_t l4_len, sum = 0, hdr_len;
    uint16_t csum_off;

    if (wd_parse_packet(pkt + l2_len, len - l2_len, &info) != 0 || info.fragment ||
        info.transport_off < 0)
        return 0;
    if (info.protocol != IPPROTO_TCP && info.protocol != IPPROTO_UDP)
        return 0;
    ip = pkt + l2_len + info.ip_off;
    th = pkt + l2_len + info.transport_off;
    l4_len = len - l2_len - (uint32_t)info.transport_off;
    hdr_len = l2_len + (uint32_t)(info.payload_off >= 0 ? info.payload_off : info.transport_off);
    if (info.protocol == IPPROTO_TCP) {
        csum_off = 16;
        vh->gso_type = info.ipv6 ? VIRTIO_NET_HDR_GSO_TCPV6 : VIRTIO_NET_HDR_GSO_TCPV4;
        if (!gso_size)
            gso_size = (uint16_t)(mtu - (hdr_len - l2_len));
    } else {
#ifdef VIRTIO_NET_HDR_GSO_UDP_L4
        csum_off = 6;
        vh->gso_type = VIRTIO_NET_HDR_GSO_UDP_L4;
        if (!gso_size)
            gso_size = (uint16_t)(mtu - (hdr_len - l2_len));
#else
        return 0;
#endif
    }
    if (info.ipv6) {
        uint8_t zero_proto[4] = {0, 0, 0, info.protocol};
        uint8_t l4len_be[4] = {(uint8_t)(l4_len >> 24), (uint8_t)(l4_len >> 16),
                               (uint8_t)(l4_len >> 8), (uint8_t)l4_len};
        sum = csum_add(sum, ip + 8, 32);
        sum = csum_add(sum, l4len_be, 4);
        sum = csum_add(sum, zero_proto, 4);
    } else {
        uint8_t proto_len[4] = {0, info.protocol, (uint8_t)(l4_len >> 8), (uint8_t)l4_len};
        sum = csum_add(sum, ip + 12, 8);
        sum = csum_add(sum, proto_len, 4);
    }
    {
        uint16_t pseudo = csum_fold32(sum);
        th[csum_off] = (uint8_t)(pseudo >> 8);
        th[csum_off + 1] = (uint8_t)pseudo;
    }
    vh->flags = VIRTIO_NET_HDR_F_NEEDS_CSUM;
    vh->hdr_len = (uint16_t)hdr_len;
    vh->gso_size = gso_size;
    vh->csum_start = (uint16_t)(l2_len + (uint32_t)info.transport_off);
    vh->csum_offset = csum_off;
    return 1;
}

static int query_mtu(int ifindex)
{
    struct ifreq ifr;
    int fd, mtu = 1500;
    memset(&ifr, 0, sizeof(ifr));
    if (!if_indextoname((unsigned)ifindex, ifr.ifr_name))
        return mtu;
    fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (fd < 0)
        return mtu;
    if (ioctl(fd, SIOCGIFMTU, &ifr) == 0)
        mtu = ifr.ifr_mtu;
    close(fd);
    return mtu;
}

/* MTU lookups are cached for a second; called with slock held. */
static int get_mtu(struct ebpfdivert_handle *h, int ifindex)
{
    int64_t now = now_ns();
    int i, victim = 0;
    for (i = 0; i < MTU_CACHE; i++) {
        if (h->mtu_cache[i].ifindex == ifindex &&
            now - h->mtu_cache[i].stamp < 1000000000LL)
            return h->mtu_cache[i].mtu;
        if (h->mtu_cache[i].stamp < h->mtu_cache[victim].stamp)
            victim = i;
    }
    h->mtu_cache[victim].ifindex = ifindex;
    h->mtu_cache[victim].mtu = query_mtu(ifindex);
    h->mtu_cache[victim].stamp = now;
    return h->mtu_cache[victim].mtu;
}

static int get_hwaddr(int ifindex, uint8_t mac[6], int *has_l2)
{
    struct ifreq ifr;
    int fd;
    memset(&ifr, 0, sizeof(ifr));
    *has_l2 = 1;
    memset(mac, 0, 6);
    if (!if_indextoname((unsigned)ifindex, ifr.ifr_name))
        return -ENODEV;
    fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (fd < 0)
        return -errno;
    if (ioctl(fd, SIOCGIFHWADDR, &ifr) == 0) {
        unsigned short type = ifr.ifr_hwaddr.sa_family;
        if (type == ARPHRD_ETHER || type == ARPHRD_LOOPBACK)
            memcpy(mac, ifr.ifr_hwaddr.sa_data, 6);
        else
            *has_l2 = 0;
    }
    close(fd);
    return 0;
}

/* Get (or create) the AF_PACKET socket that sends with `mark`.  slock held. */
static int packet_sock(struct ebpfdivert_handle *h, uint32_t mark, int redirect)
{
    int i, fd, one = 1;
    struct inject_sock *ns;
    for (i = 0; i < h->nsocks; i++)
        if (h->socks[i].mark == mark)
            return h->socks[i].fd;
    fd = socket(AF_PACKET, SOCK_RAW | SOCK_CLOEXEC, 0);
    if (fd < 0)
        return -errno;
    if (setsockopt(fd, SOL_SOCKET, SO_MARK, &mark, sizeof(mark)) != 0 ||
        setsockopt(fd, SOL_PACKET, PACKET_VNET_HDR, &one, sizeof(one)) != 0) {
        int err = -errno;
        close(fd);
        return err;
    }
    if (redirect) {
        int prio = (int)(REDIRECT_PRIO_MAGIC | (h->tc_prio & 0xFFFF));
        if (setsockopt(fd, SOL_SOCKET, SO_PRIORITY, &prio, sizeof(prio)) != 0) {
            int err = -errno;
            close(fd);
            return err;
        }
    }
    ns = realloc(h->socks, (size_t)(h->nsocks + 1) * sizeof(*ns));
    if (!ns) {
        close(fd);
        return -ENOMEM;
    }
    h->socks = ns;
    h->socks[h->nsocks].mark = mark;
    h->socks[h->nsocks].fd = fd;
    h->nsocks++;
    return fd;
}

static int send_af_packet(struct ebpfdivert_handle *h, int out_ifindex, uint32_t mark,
                          int redirect, const uint8_t *l2, uint32_t l2_len,
                          const uint8_t *pkt, uint32_t len, uint16_t gso_size)
{
    struct virtio_net_hdr vh;
    struct sockaddr_ll sll;
    uint8_t *frame;
    uint32_t flen = l2_len + len;
    int fd, mtu, ret;
    ssize_t n;

    frame = malloc(sizeof(vh) + flen);
    if (!frame)
        return -ENOMEM;
    memset(&vh, 0, sizeof(vh));
    memcpy(frame + sizeof(vh), l2, l2_len);
    memcpy(frame + sizeof(vh) + l2_len, pkt, len);

    memset(&sll, 0, sizeof(sll));
    sll.sll_family = AF_PACKET;
    sll.sll_ifindex = out_ifindex;
    sll.sll_protocol = htons((pkt[0] >> 4) == 6 ? ETH_P_IPV6 : ETH_P_IP);
    sll.sll_halen = 0;

    pthread_mutex_lock(&h->slock);
    if (len > 576) {
        mtu = get_mtu(h, redirect ? (int)(mark & 0xFFFF) : out_ifindex);
        if (len > (uint32_t)mtu)
            prepare_gso(frame + sizeof(vh), flen, l2_len, (uint16_t)mtu, gso_size, &vh);
    }
    memcpy(frame, &vh, sizeof(vh));
    fd = packet_sock(h, mark, redirect);
    if (fd < 0) {
        pthread_mutex_unlock(&h->slock);
        free(frame);
        return fd;
    }
    n = sendto(fd, frame, sizeof(vh) + flen, 0, (struct sockaddr *)&sll, sizeof(sll));
    ret = n < 0 ? -errno : 0;
    pthread_mutex_unlock(&h->slock);
    free(frame);
    return ret;
}

static int raw_sock(struct ebpfdivert_handle *h, int v6)
{
    int *slot = v6 ? &h->raw6 : &h->raw4;
    uint32_t mark = LOOP_PREVENTION_MARK | (h->tc_prio & 0xFFFF);
    int fd;
    if (*slot >= 0)
        return *slot;
    fd = socket(v6 ? AF_INET6 : AF_INET, SOCK_RAW | SOCK_CLOEXEC, IPPROTO_RAW);
    if (fd < 0)
        return -errno;
    if (setsockopt(fd, SOL_SOCKET, SO_MARK, &mark, sizeof(mark)) != 0) {
        int err = -errno;
        close(fd);
        return err;
    }
    *slot = fd;
    return fd;
}

static int send_raw_ip(struct ebpfdivert_handle *h, const uint8_t *pkt, uint32_t len)
{
    int v6 = (pkt[0] >> 4) == 6, fd, ret;
    ssize_t n;

    pthread_mutex_lock(&h->slock);
    fd = raw_sock(h, v6);
    if (fd < 0) {
        pthread_mutex_unlock(&h->slock);
        return fd;
    }
    if (v6) {
        struct sockaddr_in6 sa;
        memset(&sa, 0, sizeof(sa));
        sa.sin6_family = AF_INET6;
        memcpy(&sa.sin6_addr, pkt + 24, 16);
        if (IN6_IS_ADDR_LOOPBACK(&sa.sin6_addr) || IN6_IS_ADDR_LINKLOCAL(&sa.sin6_addr))
            sa.sin6_scope_id = (uint32_t)h->lo_ifindex;
        n = sendto(fd, pkt, len, 0, (struct sockaddr *)&sa, sizeof(sa));
    } else {
        struct sockaddr_in sa;
        memset(&sa, 0, sizeof(sa));
        sa.sin_family = AF_INET;
        memcpy(&sa.sin_addr, pkt + 16, 4);
        n = sendto(fd, pkt, len, 0, (struct sockaddr *)&sa, sizeof(sa));
    }
    ret = n < 0 ? -errno : 0;
    pthread_mutex_unlock(&h->slock);
    return ret;
}

static int inject(struct ebpfdivert_handle *h, const uint8_t *pkt0, uint32_t len,
                  const struct ebpfdivert_address *addr, int fix_checksums)
{
    const struct l2_stash *stash = get_stash(addr);
    uint32_t prevent = LOOP_PREVENTION_MARK | (h->tc_prio & 0xFFFF);
    int ifindex = (int)addr->network.if_idx;
    int outbound = addr->outbound || addr->layer == EBPFDIVERT_LAYER_NETWORK_FORWARD;
    uint8_t *pkt;
    int ret, ver;

    if (len < 20)
        return -EINVAL;
    ver = pkt0[0] >> 4;
    if (ver != 4 && ver != 6)
        return -EINVAL;
    pkt = malloc(len);
    if (!pkt)
        return -ENOMEM;
    memcpy(pkt, pkt0, len);
    if (fix_checksums) {
        /* WinDivert semantics: clear checksum flags ask for recalculation. */
        uint64_t no = 0;
        if (addr->ip_checksum)
            no |= 1;
        if (addr->tcp_checksum)
            no |= 8;
        if (addr->udp_checksum)
            no |= 16;
        wd_calc_checksums(pkt, len, NULL, no);
    }

    if (addr->loopback || (ifindex == h->lo_ifindex && ifindex > 0)) {
        /*
         * Loopback: go through the local output path.  Frames sent on lo
         * with AF_PACKET have no route and 127/8 or ::1 sources are then
         * dropped as martians (unless route_localnet is set).
         */
        ret = send_raw_ip(h, pkt, len);
    } else if (outbound) {
        if (stash && ifindex > 0) {
            ret = send_af_packet(h, ifindex, prevent, 0, stash->data, stash->len, pkt, len,
                                 stash->gso_size);
        } else {
            ret = send_raw_ip(h, pkt, len);
        }
    } else if (ifindex <= 0) {
        /* Inbound without an interface: deliver locally. */
        ret = send_raw_ip(h, pkt, len);
    } else {
        /* Inbound: send through lo, the lo ingress hook redirects it to the
         * target's ingress.  lo is an Ethernet-like device, so a MAC header
         * is always needed; for L3 targets the redirect strips it. */
        uint8_t eth[ETH_HLEN];
        const uint8_t *l2 = eth;
        uint16_t gso = 0;
        if (stash && stash->len == ETH_HLEN) {
            l2 = stash->data;
            gso = stash->gso_size;
        } else {
            int has_l2;
            memset(eth, 0, sizeof(eth));
            get_hwaddr(ifindex, eth, &has_l2);
            eth[12] = ver == 6 ? 0x86 : 0x08;
            eth[13] = ver == 6 ? 0xDD : 0x00;
            if (stash)
                gso = stash->gso_size;
        }
        ret = send_af_packet(h, h->lo_ifindex, REDIRECT_MARK_MASK | ((uint32_t)ifindex & 0xFFFF),
                             1, l2, ETH_HLEN, pkt, len, gso);
    }
    free(pkt);
    return ret;
}

static int ebpfdivert_send_impl(ebpfdivert_handle_t *h, const void *pkt, uint32_t pkt_len, uint32_t *send_len,
                    const struct ebpfdivert_address *addr)
{
    int ret;
    if (!h || !pkt || !addr)
        return -EINVAL;
    if (h->flags & EBPFDIVERT_FLAG_RECV_ONLY)
        return -EPERM;
    if (h->layer != EBPFDIVERT_LAYER_NETWORK && h->layer != EBPFDIVERT_LAYER_NETWORK_FORWARD)
        return -EINVAL;
    if (__atomic_load_n(&h->shut_send, __ATOMIC_ACQUIRE))
        return -ESHUTDOWN;
    if (pkt_len > EBPFDIVERT_MTU_MAX)
        return -EMSGSIZE;
    ret = inject(h, pkt, pkt_len, addr, 1);
    if (ret == 0 && send_len)
        *send_len = pkt_len;
    return ret;
}

static int ebpfdivert_send_ex_impl(ebpfdivert_handle_t *h, const void *pkt, uint32_t pkt_len, uint32_t *send_len,
                       const struct ebpfdivert_address *addrs, uint32_t addr_len)
{
    const uint8_t *p = pkt;
    uint32_t off = 0, i, sent = 0;
    int ret = 0;
    struct wd_packet_info info;

    if (!h || !pkt || !addrs)
        return -EINVAL;
    for (i = 0; i < addr_len && off < pkt_len; i++) {
        uint32_t plen;
        if (wd_parse_packet(p + off, pkt_len - off, &info) != 0)
            return i ? 0 : -EINVAL;
        /* Total length from the IP header (packets are back-to-back). */
        if (info.ipv6)
            plen = 40u + (uint32_t)((p[off + 4] << 8) | p[off + 5]);
        else
            plen = (uint32_t)((p[off + 2] << 8) | p[off + 3]);
        if (plen == 0 || off + plen > pkt_len)
            return -EINVAL;
        ret = ebpfdivert_send_impl(h, p + off, plen, NULL, &addrs[i]);
        if (ret)
            break;
        off += plen;
        sent += plen;
    }
    if (send_len)
        *send_len = sent;
    return (sent == 0 && ret) ? ret : 0;
}

/****************************************************************************/
/* Open / close                                                             */
/****************************************************************************/

static int is_event_layer(int layer)
{
    return layer == EBPFDIVERT_LAYER_FLOW || layer == EBPFDIVERT_LAYER_SOCKET;
}

static int write_config(struct ebpfdivert_handle *h)
{
    uint32_t key = 0;
    int ret = 0;
    if (h->cfg_fd < 0)
        return 0;
    pthread_mutex_lock(&h->cfg_lock);
    if (is_event_layer(h->layer)) {
        h->evcfg.heartbeat_ns = (uint64_t)now_ns();
        h->evcfg.heartbeat_timeout_ns = HEARTBEAT_TIMEOUT_NS;
        if (bpf_map_update_elem(h->cfg_fd, &key, &h->evcfg, BPF_ANY) != 0)
            ret = -errno;
    } else {
        h->cfg.heartbeat_ns = (uint64_t)now_ns();
        h->cfg.heartbeat_timeout_ns = HEARTBEAT_TIMEOUT_NS;
        if (bpf_map_update_elem(h->cfg_fd, &key, &h->cfg, BPF_ANY) != 0)
            ret = -errno;
    }
    pthread_mutex_unlock(&h->cfg_lock);
    return ret;
}

static int load_rules(struct ebpfdivert_handle *h)
{
    struct pf_result *res = malloc(sizeof(*res));
    struct bpf_map *m4 = bpf_object__find_map_by_name(h->obj, "filter_rules");
    struct bpf_map *m6 = bpf_object__find_map_by_name(h->obj, "filter_rules_ipv6");
    uint16_t action = 0;
    uint32_t i;
    int err;

    if (!res)
        return -ENOMEM;
    if (!m4 || !m6) {
        free(res);
        return -ENOENT;
    }
    err = pf_lower(h->filter, res);
    if (err) {
        free(res);
        return err;
    }
    h->exact = res->exact;
    if (h->flags & EBPFDIVERT_FLAG_SNIFF)
        action = MATCH_SNIFF;
    else if ((h->flags & EBPFDIVERT_FLAG_DROP) && res->exact)
        action = MATCH_DROP;
    for (i = 0; i < res->n4; i++) {
        res->v4[i].match_mask |= action;
        if (bpf_map_update_elem(bpf_map__fd(m4), &i, &res->v4[i], BPF_ANY) != 0) {
            err = -errno;
            break;
        }
    }
    for (i = 0; !err && i < res->n6; i++) {
        res->v6[i].match_mask |= action;
        if (bpf_map_update_elem(bpf_map__fd(m6), &i, &res->v6[i], BPF_ANY) != 0) {
            err = -errno;
            break;
        }
    }
    free(res);
    return err;
}

static int choose_tc_prio(struct ebpfdivert_handle *h, int reg_fd)
{
    if (h->priority != 0) {
        h->tc_prio = (uint32_t)(AUTO_PRIORITY_BASE - (int32_t)h->priority);
        return 0;
    }
    /* Priority 0: after every existing handle. */
    {
        uint32_t max = 0;
        if (reg_fd >= 0)
            max = registry_max_tc_prio(reg_fd);
        pthread_mutex_lock(&local_prio_lock);
        if (local_max_tc_prio > max)
            max = local_max_tc_prio;
        h->tc_prio = max >= AUTO_PRIORITY_BASE ? max + 1 : AUTO_PRIORITY_BASE;
        if (h->tc_prio > 0xFFFF)
            h->tc_prio = 0xFFFF;
        if (h->tc_prio > local_max_tc_prio)
            local_max_tc_prio = h->tc_prio;
        pthread_mutex_unlock(&local_prio_lock);
    }
    return 0;
}

static void registry_add(struct ebpfdivert_handle *h, int reg_fd)
{
    struct reg_entry *e;
    int i;
    if (reg_fd < 0)
        return;
    e = calloc(1, sizeof(*e));
    if (!e)
        return;
    e->pid = (uint32_t)getpid();
    e->pid_start = proc_start_time(getpid());
    e->timestamp = now_ns();
    e->tc_prio = h->tc_prio;
    e->flags = h->flags;
    e->layer = (uint32_t)h->layer;
    e->priority = h->priority;
    for (i = 0; i < h->natt && e->nattach < REG_MAX_ATTACH; i++) {
        struct attachment *a = &h->att[i];
        if (!a->legacy)
            continue;
        e->legacy = 1;
        e->attach[e->nattach].ifindex = (uint32_t)a->ifindex;
        e->attach[e->nattach].attach_point = a->hook.attach_point;
        e->attach[e->nattach].handle = a->opts.handle;
        e->attach[e->nattach].priority = a->opts.priority;
        e->nattach++;
    }
    if (h->filter) {
        int n = wd_filter_serialize(h->filter, e->filter, sizeof(e->filter));
        e->filter_len = n > 0 ? (uint32_t)n : 0;
    }
    do {
        if (getrandom_u64(&h->reg_id) != 0)
            break;
    } while (h->reg_id == 0);
    if (h->reg_id && bpf_map_update_elem(reg_fd, &h->reg_id, e, BPF_NOEXIST) != 0)
        h->reg_id = 0;
    free(e);
}

static void free_handle(struct ebpfdivert_handle *h)
{
    struct qentry *e, *n;
    int i;
    if (!h)
        return;
    detach_all(h);
    free(h->att);
    for (i = 0; i < h->nlinks; i++)
        bpf_link__destroy(h->links[i]);
    h->nlinks = 0;
    if (h->rb)
        ring_buffer__free(h->rb);
    if (h->obj)
        bpf_object__close(h->obj);
    for (i = 0; i < h->nsocks; i++)
        close(h->socks[i].fd);
    free(h->socks);
    if (h->raw4 >= 0)
        close(h->raw4);
    if (h->raw6 >= 0)
        close(h->raw6);
    for (i = 0; i < h->nlinks; i++)
        bpf_link__destroy(h->links[i]);
    free(h->udp);
    for (i = 0; i < (int)h->nseen; i++)
        free(h->seen[i].filter);
    free(h->seen);
    if (h->timer_fd >= 0)
        close(h->timer_fd);
    if (h->epfd >= 0)
        close(h->epfd);
    if (h->wake_fd >= 0)
        close(h->wake_fd);
    for (e = h->qhead; e; e = n) {
        n = e->next;
        free(e);
    }
    wd_filter_free(h->filter);
    pthread_mutex_destroy(&h->rlock);
    pthread_cond_destroy(&h->rcond);
    pthread_mutex_destroy(&h->cfg_lock);
    pthread_mutex_destroy(&h->qlock);
    pthread_mutex_destroy(&h->poll_lock);
    pthread_mutex_destroy(&h->slock);
    free(h);
}

static int open_network(struct ebpfdivert_handle *h, const struct ebpfdivert_open_opts *opts)
{
    const char *const *ifnames = NULL;
    struct bpf_map *ring, *cfg, *stats;
    uint32_t ring_bytes = DEFAULT_RING_BYTES;
    struct epoll_event ev;
    int err, reg_fd = -1, lock_fd = -1;

    if (opts && opts->sz >= offsetof(struct ebpfdivert_open_opts, ifnames) + sizeof(opts->ifnames))
        ifnames = opts->ifnames;
    if (opts && opts->sz >= offsetof(struct ebpfdivert_open_opts, ring_bytes) + sizeof(opts->ring_bytes) &&
        opts->ring_bytes)
        ring_bytes = opts->ring_bytes;
    /* Ring buffer size must be a power of two >= page size. */
    {
        uint32_t p = 4096;
        while (p < ring_bytes && p < (1u << 30))
            p <<= 1;
        ring_bytes = p;
    }

    h->obj = embedded_object_open();
    if (!h->obj)
        return -errno ? -errno : -ENOENT;
    ring = bpf_object__find_map_by_name(h->obj, "pcap_ringbuf");
    if (ring)
        bpf_map__set_max_entries(ring, ring_bytes);
    err = bpf_object__load(h->obj);
    if (err)
        return err;
    cfg = bpf_object__find_map_by_name(h->obj, "config_map");
    stats = bpf_object__find_map_by_name(h->obj, "stats_map");
    if (!ring || !cfg || !stats)
        return -ENOENT;
    h->cfg_fd = bpf_map__fd(cfg);
    h->stats_fd = bpf_map__fd(stats);

    err = load_rules(h);
    if (err)
        return err;

    h->cfg.snaplen = DIVERT_MAX_PACKET;
    h->cfg.loop_prevention_mark = LOOP_PREVENTION_MARK;
    h->cfg.lo_ifindex = (uint32_t)h->lo_ifindex;
    if (h->flags & EBPFDIVERT_FLAG_FRAGMENTS)
        h->cfg.flags |= CFG_F_FRAGMENTS;
    if (h->layer == EBPFDIVERT_LAYER_NETWORK_FORWARD)
        h->cfg.flags |= CFG_F_FORWARD;
    if (read_sysctl_int("/proc/sys/net/ipv4/ip_forward") ||
        read_sysctl_int("/proc/sys/net/ipv6/conf/all/forwarding"))
        h->cfg.flags |= CFG_F_FWD_CHECK;
    {
        uint64_t ff = wd_filter_flags(h->filter);
        if (!(ff & (1ull << 4)))    /* WINDIVERT_FILTER_FLAG_INBOUND */
            h->cfg.flags |= CFG_F_NO_INBOUND;
        if (!(ff & (1ull << 5)))    /* WINDIVERT_FILTER_FLAG_OUTBOUND */
            h->cfg.flags |= CFG_F_NO_OUTBOUND;
    }

    if (!(h->flags & EBPFDIVERT_FLAG_SEND_ONLY)) {
        h->rb = ring_buffer__new(bpf_map__fd(ring), ring_callback, h, NULL);
        if (!h->rb)
            return -errno ? -errno : -ENOMEM;
        memset(&ev, 0, sizeof(ev));
        ev.events = EPOLLIN;
        if (epoll_ctl(h->epfd, EPOLL_CTL_ADD, ring_buffer__epoll_fd(h->rb), &ev) != 0)
            return -errno;
    }

    lock_fd = registry_lock();
    reg_fd = registry_open();
    if (reg_fd >= 0)
        registry_reap(reg_fd);
    choose_tc_prio(h, reg_fd);
    h->cfg.priority = h->tc_prio;
    err = write_config(h);
    if (!err && !(h->flags & EBPFDIVERT_FLAG_SEND_ONLY)) {
        err = attach_interfaces(h, ifnames);
        if (!err)
            err = write_config(h);      /* CFG_F_SKIP_LO may have been set */
    }
    if (!err)
        registry_add(h, reg_fd);
    if (reg_fd >= 0)
        close(reg_fd);
    registry_unlock(lock_fd);
    return err;
}


/****************************************************************************/
/* FLOW and SOCKET layers                                                   */
/****************************************************************************/

static void words_from_net(uint32_t *w, const uint8_t *b)
{
    int i;
    for (i = 0; i < 4; i++)
        w[3 - i] = ((uint32_t)b[4 * i] << 24) | ((uint32_t)b[4 * i + 1] << 16) |
                   ((uint32_t)b[4 * i + 2] << 8) | b[4 * i + 3];
}

static int addr_is_loopback(const uint8_t *a)
{
    static const uint8_t v6lo[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
    if (a[10] == 0xFF && a[11] == 0xFF && !a[0] && !a[8] && !a[9])
        return a[12] == 127;
    return memcmp(a, v6lo, 16) == 0;
}

/* Turn a kernel event into a queued, filter-checked WinDivert event. */
static void deliver_event(struct ebpfdivert_handle *h, const struct divert_event *ev, uint8_t event)
{
    struct qentry *e = calloc(1, sizeof(*e));
    struct ebpfdivert_data_socket *d;
    if (!e)
        return;
    e->len = 0;
    e->addr.timestamp = (int64_t)ev->timestamp;
    e->addr.layer = (uint32_t)h->layer;
    e->addr.event = event;
    e->addr.sniffed = !!(h->flags & EBPFDIVERT_FLAG_SNIFF);
    e->addr.ipv6 = (ev->family == 6);
    e->addr.loopback = addr_is_loopback(ev->local_addr) || addr_is_loopback(ev->remote_addr);
    /* Flow and socket data share the same layout. */
    d = &e->addr.socket;
    d->endpoint_id = ev->endpoint_id;
    d->parent_endpoint_id = ev->parent_endpoint_id;
    d->process_id = ev->pid;
    words_from_net(d->local_addr, ev->local_addr);
    words_from_net(d->remote_addr, ev->remote_addr);
    d->local_port = ev->local_port;
    d->remote_port = ev->remote_port;
    d->protocol = ev->protocol;
    if (wd_filter_eval(h->filter, NULL, 0, &e->addr) != 1) {
        free(e);
        return;
    }
    e->addr.timestamp = (int64_t)ev->timestamp;
    queue_push(h, e);
}

static void udp_track(struct ebpfdivert_handle *h, const struct divert_event *ev)
{
    if (h->nudp == UDP_TRACK_MAX) {
        /* Forget the oldest half; those flows end without DELETED. */
        memmove(h->udp, h->udp + UDP_TRACK_MAX / 2, (UDP_TRACK_MAX / 2) * sizeof(*h->udp));
        h->nudp = UDP_TRACK_MAX / 2;
    }
    if (!h->udp) {
        h->udp = calloc(UDP_TRACK_MAX, sizeof(*h->udp));
        if (!h->udp)
            return;
    }
    h->udp[h->nudp++] = *ev;
}

/* A UDP socket went away: its flows are deleted. */
static void udp_release(struct ebpfdivert_handle *h, const struct divert_event *ev)
{
    unsigned i = 0;
    while (i < h->nudp) {
        if (h->udp[i].endpoint_id == ev->endpoint_id) {
            struct divert_event del = h->udp[i];
            del.timestamp = ev->timestamp;
            deliver_event(h, &del, EBPFDIVERT_EVENT_FLOW_DELETED);
            h->udp[i] = h->udp[--h->nudp];
        } else {
            i++;
        }
    }
}

static int event_callback(void *ctx, void *data, size_t size)
{
    struct ebpfdivert_handle *h = ctx;
    const struct divert_event *ev = data;
    if (size < sizeof(*ev))
        return 0;
    if (ev->flags & EVF_UDP_RELEASE) {
        udp_release(h, ev);
        return 0;
    }
    if (h->layer == EBPFDIVERT_LAYER_FLOW && ev->protocol == IPPROTO_UDP &&
        ev->event == EBPFDIVERT_EVENT_FLOW_ESTABLISHED)
        udp_track(h, ev);
    deliver_event(h, ev, ev->event);
    return 0;
}

/* The cgroup v2 hierarchy root (where the event programs attach). */
static int open_cgroup_root(void)
{
    char line[1024], path[512] = "";
    FILE *f = fopen("/proc/self/mountinfo", "r");
    if (f) {
        while (fgets(line, sizeof(line), f)) {
            char mnt[512], *sep = strstr(line, " - cgroup2 ");
            if (!sep)
                continue;
            if (sscanf(line, "%*s %*s %*s %*s %511s", mnt) == 1) {
                snprintf(path, sizeof(path), "%s", mnt);
                break;
            }
        }
        fclose(f);
    }
    if (!path[0]) {
        /* cgroup v1 only: the event layers need the unified hierarchy. */
        errno = EOPNOTSUPP;
        return -1;
    }
    return open(path, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
}

static int attach_cgroup_prog(struct ebpfdivert_handle *h, int cg, const char *name)
{
    struct bpf_program *prog = bpf_object__find_program_by_name(h->obj, name);
    struct bpf_link *link;
    if (!prog)
        return -ENOENT;
    if (h->nlinks == EBD_MAX_LINKS)
        return -E2BIG;
    link = bpf_program__attach_cgroup(prog, cg);
    if (!link || libbpf_get_error(link)) {
        int err = link ? (int)libbpf_get_error(link) : -errno;
        pr_log(EBPFDIVERT_WARN, "ebpfdivert: attaching %s failed: %s\n", name, strerror(-err));
        return err;
    }
    h->links[h->nlinks++] = link;
    return 0;
}

static int open_events(struct ebpfdivert_handle *h, const struct ebpfdivert_open_opts *opts)
{
    static const char *const socket_progs[] = {
        "ev_sock_create", "ev_post_bind4", "ev_post_bind6", "ev_connect4", "ev_connect6",
        "ev_sockops", "ev_sock_release", NULL
    };
    static const char *const flow_progs[] = {
        "ev_sock_create", "ev_sockops", "ev_sock_release", "ev_skb_egress", "ev_skb_ingress", NULL
    };
    const char *const *progs = (h->layer == EBPFDIVERT_LAYER_SOCKET) ? socket_progs : flow_progs;
    struct event_rule rules[EVENT_RULES_MAX];
    unsigned nrules = 0, i;
    struct bpf_map *ring, *cfg, *rmap, *rodata;
    struct epoll_event ev;
    uint32_t ring_bytes = EVENT_RING_BYTES;
    int err, cg, block = 0;

    if (h->layer == EBPFDIVERT_LAYER_SOCKET && !(h->flags & EBPFDIVERT_FLAG_SNIFF)) {
        /* Blocking happens in the kernel: it must know the exact filter.
         * LISTEN and ACCEPT cannot be refused on Linux. */
        uint64_t ff = wd_filter_flags(h->filter);
        int exact;
        if (ff & (0x800ull | 0x1000ull))    /* FILTER_FLAG_EVENT_SOCKET_LISTEN/ACCEPT */
            return -EOPNOTSUPP;
        err = pf_lower_events(h->filter, rules, EVENT_RULES_MAX, &nrules, &exact);
        if (err)
            return err;
        if (!exact)
            return -EOPNOTSUPP;
        block = 1;
    }
    if (opts && opts->sz >= offsetof(struct ebpfdivert_open_opts, ring_bytes) + sizeof(opts->ring_bytes) &&
        opts->ring_bytes) {
        uint32_t p = 4096;
        while (p < opts->ring_bytes && p < (1u << 30))
            p <<= 1;
        ring_bytes = p;
    }

    h->obj = embedded_events_object_open();
    if (!h->obj)
        return errno ? -errno : -ENOENT;
    ring = bpf_object__find_map_by_name(h->obj, "event_ringbuf");
    if (ring)
        bpf_map__set_max_entries(ring, ring_bytes);
    rodata = bpf_object__find_map_by_name(h->obj, ".rodata");
    if (rodata) {
        size_t sz;
        uint32_t *have_pid = bpf_map__initial_value(rodata, &sz);
        if (have_pid && sz >= sizeof(*have_pid))
            *have_pid = libbpf_probe_bpf_helper(BPF_PROG_TYPE_CGROUP_SOCK_ADDR,
                                                BPF_FUNC_get_current_pid_tgid, NULL) > 0;
    }
    err = bpf_object__load(h->obj);
    if (err)
        return err;
    cfg = bpf_object__find_map_by_name(h->obj, "event_config_map");
    rmap = bpf_object__find_map_by_name(h->obj, "event_rules");
    if (!ring || !cfg || !rmap)
        return -ENOENT;
    h->cfg_fd = bpf_map__fd(cfg);
    for (i = 0; i < nrules; i++) {
        if (bpf_map_update_elem(bpf_map__fd(rmap), &i, &rules[i], BPF_ANY) != 0)
            return -errno;
    }
    h->evcfg.flags = (h->layer == EBPFDIVERT_LAYER_SOCKET ? EVCFG_F_SOCKET : 0) |
                     (block ? EVCFG_F_BLOCK : 0);
    err = write_config(h);
    if (err)
        return err;

    h->rb = ring_buffer__new(bpf_map__fd(ring), event_callback, h, NULL);
    if (!h->rb)
        return errno ? -errno : -ENOMEM;
    memset(&ev, 0, sizeof(ev));
    ev.events = EPOLLIN;
    if (epoll_ctl(h->epfd, EPOLL_CTL_ADD, ring_buffer__epoll_fd(h->rb), &ev) != 0)
        return -errno;

    cg = open_cgroup_root();
    if (cg < 0)
        return -errno;
    for (i = 0; progs[i]; i++) {
        err = attach_cgroup_prog(h, cg, progs[i]);
        if (err)
            break;
    }
    close(cg);
    return err;
}

/****************************************************************************/
/* REFLECT layer                                                            */
/****************************************************************************/

static void deliver_reflect(struct ebpfdivert_handle *h, const struct reflect_seen *r, uint8_t event)
{
    uint32_t len = r->filter_len;
    struct qentry *e = calloc(1, sizeof(*e) + len);
    if (!e)
        return;
    e->len = len;
    memcpy(e->data, r->filter, len);
    e->addr.timestamp = now_ns();
    e->addr.layer = EBPFDIVERT_LAYER_REFLECT;
    e->addr.event = event;
    e->addr.sniffed = 1;
    e->addr.reflect = r->data;
    if (wd_filter_eval(h->filter, e->data, e->len, &e->addr) != 1) {
        free(e);
        return;
    }
    queue_push(h, e);
}

/* Report handles opened or closed since the last poll (all of them at first). */
static void reflect_poll(struct ebpfdivert_handle *h)
{
    uint64_t key, next, *prev = NULL, ticks;
    struct reg_entry *e;
    unsigned i;
    uint8_t *alive;
    int reg_fd;

    if (h->timer_fd >= 0 && read(h->timer_fd, &ticks, sizeof(ticks)) != sizeof(ticks) && h->nseen)
        return;     /* not due yet */
    reg_fd = bpf_obj_get(REGISTRY_PIN);
    if (reg_fd < 0)
        return;
    e = malloc(sizeof(*e));
    alive = calloc(h->nseen + 1, 1);
    if (!e || !alive) {
        free(e);
        free(alive);
        close(reg_fd);
        return;
    }
    pthread_mutex_lock(&h->poll_lock);
    while (bpf_map_get_next_key(reg_fd, prev, &next) == 0) {
        key = next;
        prev = &key;
        if (bpf_map_lookup_elem(reg_fd, &key, e) != 0)
            continue;
        for (i = 0; i < h->nseen; i++)
            if (h->seen[i].id == key)
                break;
        if (i < h->nseen) {
            alive[i] = 1;
            continue;
        }
        {
            struct reflect_seen *ns = realloc(h->seen, (h->nseen + 1) * sizeof(*ns));
            uint8_t *na;
            struct reflect_seen *r;
            if (!ns)
                continue;
            h->seen = ns;
            na = realloc(alive, h->nseen + 2);
            if (!na)
                continue;
            alive = na;
            r = &h->seen[h->nseen];
            memset(r, 0, sizeof(*r));
            r->id = key;
            r->data.timestamp = e->timestamp;
            r->data.process_id = e->pid;
            r->data.layer = e->layer;
            r->data.flags = e->flags;
            r->data.priority = e->priority;
            r->filter_len = e->filter_len <= REG_FILTER_MAX ? e->filter_len : 0;
            r->filter = malloc(r->filter_len + 1);
            if (r->filter)
                memcpy(r->filter, e->filter, r->filter_len);
            else
                r->filter_len = 0;
            alive[h->nseen] = 1;
            h->nseen++;
            deliver_reflect(h, r, EBPFDIVERT_EVENT_REFLECT_OPEN);
        }
    }
    i = 0;
    while (i < h->nseen) {
        if (!alive[i]) {
            deliver_reflect(h, &h->seen[i], EBPFDIVERT_EVENT_REFLECT_CLOSE);
            free(h->seen[i].filter);
            h->seen[i] = h->seen[h->nseen - 1];
            alive[i] = alive[h->nseen - 1];
            h->nseen--;
        } else {
            i++;
        }
    }
    pthread_mutex_unlock(&h->poll_lock);
    free(alive);
    free(e);
    close(reg_fd);
}

static int open_reflect(struct ebpfdivert_handle *h)
{
    struct itimerspec its;
    struct epoll_event ev;
    h->timer_fd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC);
    if (h->timer_fd < 0)
        return -errno;
    memset(&its, 0, sizeof(its));
    its.it_value.tv_nsec = 1;
    its.it_interval.tv_nsec = REFLECT_PERIOD_MS * 1000000L;
    if (timerfd_settime(h->timer_fd, 0, &its, NULL) != 0)
        return -errno;
    memset(&ev, 0, sizeof(ev));
    ev.events = EPOLLIN;
    if (epoll_ctl(h->epfd, EPOLL_CTL_ADD, h->timer_fd, &ev) != 0)
        return -errno;
    return 0;
}

/* Register an event or REFLECT handle (network handles register while
 * attaching, under the same lock that picks their priority). */
static void register_handle(struct ebpfdivert_handle *h)
{
    int lock_fd = registry_lock(), reg_fd = registry_open();
    if (reg_fd >= 0) {
        registry_reap(reg_fd);
        registry_add(h, reg_fd);
        close(reg_fd);
    }
    registry_unlock(lock_fd);
}

ebpfdivert_handle_t *ebpfdivert_open(const char *filter, int layer, int16_t priority,
                                     uint64_t flags, const struct ebpfdivert_open_opts *opts)
{
    struct ebpfdivert_handle *h;
    const char *err_str;
    unsigned err_pos;
    struct epoll_event ev;
    int err;

    if (!filter || layer < EBPFDIVERT_LAYER_NETWORK || layer > EBPFDIVERT_LAYER_REFLECT ||
        priority < EBPFDIVERT_PRIORITY_LOWEST || priority > EBPFDIVERT_PRIORITY_HIGHEST ||
        (flags & ~(uint64_t)0x3F) ||
        ((flags & EBPFDIVERT_FLAG_SNIFF) && (flags & EBPFDIVERT_FLAG_DROP)) ||
        ((flags & EBPFDIVERT_FLAG_RECV_ONLY) && (flags & EBPFDIVERT_FLAG_SEND_ONLY))) {
        errno = EINVAL;
        return NULL;
    }
    /* Same per-layer rules as WinDivert. */
    if (((layer == EBPFDIVERT_LAYER_FLOW || layer == EBPFDIVERT_LAYER_REFLECT) &&
         (flags & (EBPFDIVERT_FLAG_SNIFF | EBPFDIVERT_FLAG_RECV_ONLY)) !=
             (EBPFDIVERT_FLAG_SNIFF | EBPFDIVERT_FLAG_RECV_ONLY)) ||
        (layer == EBPFDIVERT_LAYER_SOCKET && !(flags & EBPFDIVERT_FLAG_RECV_ONLY))) {
        errno = EINVAL;
        return NULL;
    }

    ensure_libbpf_setup();
    h = calloc(1, sizeof(*h));
    if (!h) {
        errno = ENOMEM;
        return NULL;
    }
    pthread_mutex_init(&h->rlock, NULL);
    pthread_cond_init(&h->rcond, NULL);
    pthread_mutex_init(&h->cfg_lock, NULL);
    pthread_mutex_init(&h->qlock, NULL);
    pthread_mutex_init(&h->poll_lock, NULL);
    pthread_mutex_init(&h->slock, NULL);
    h->layer = layer;
    h->flags = flags;
    h->priority = priority;
    h->raw4 = h->raw6 = -1;
    h->cfg_fd = h->stats_fd = -1;
    h->timer_fd = -1;
    h->queue_length = EBPFDIVERT_PARAM_QUEUE_LENGTH_DEFAULT;
    h->queue_time = EBPFDIVERT_PARAM_QUEUE_TIME_DEFAULT;
    h->queue_size = EBPFDIVERT_PARAM_QUEUE_SIZE_DEFAULT;
    h->lo_ifindex = (int)if_nametoindex("lo");
    if (h->lo_ifindex <= 0)
        h->lo_ifindex = 1;
    h->wake_fd = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
    h->epfd = epoll_create1(EPOLL_CLOEXEC);
    if (h->wake_fd < 0 || h->epfd < 0) {
        err = -errno;
        goto fail;
    }
    memset(&ev, 0, sizeof(ev));
    ev.events = EPOLLIN;
    if (epoll_ctl(h->epfd, EPOLL_CTL_ADD, h->wake_fd, &ev) != 0) {
        err = -errno;
        goto fail;
    }

    err = wd_filter_compile(filter, layer, &h->filter, &err_str, &err_pos);
    if (err) {
        pr_log(EBPFDIVERT_DEBUG, "ebpfdivert: filter error: %s at %u\n",
               err_str ? err_str : "?", err_pos);
        goto fail;
    }

    switch (layer) {
    case EBPFDIVERT_LAYER_NETWORK:
    case EBPFDIVERT_LAYER_NETWORK_FORWARD:
        err = open_network(h, opts);
        break;
    case EBPFDIVERT_LAYER_FLOW:
    case EBPFDIVERT_LAYER_SOCKET:
        err = open_events(h, opts);
        if (!err)
            register_handle(h);
        break;
    default:
        err = open_reflect(h);
        if (!err)
            register_handle(h);
        break;
    }
    if (err)
        goto fail;
    heartbeat_add(h);
    return h;

fail:
    free_handle(h);
    errno = -err;
    return NULL;
}

int ebpfdivert_open_ex(const char *filter, int layer, int16_t priority, uint64_t flags,
                       const struct ebpfdivert_open_opts *opts, ebpfdivert_handle_t **out)
{
    if (!out)
        return -EINVAL;
    errno = 0;
    *out = ebpfdivert_open(filter, layer, priority, flags, opts);
    if (*out)
        return 0;
    return errno ? -errno : -EIO;
}

int ebpfdivert_close(ebpfdivert_handle_t *h)
{
    int reg_fd, lock_fd;
    if (!h)
        return -EINVAL;
    pthread_mutex_lock(&h->rlock);
    if (h->closing) {
        pthread_mutex_unlock(&h->rlock);
        return -EBADF;
    }
    h->closing = 1;
    pthread_mutex_unlock(&h->rlock);
    /* Wake blocked receivers, then wait for every call in progress. */
    ebpfdivert_shutdown(h, EBPFDIVERT_SHUTDOWN_BOTH);
    heartbeat_remove(h);
    pthread_mutex_lock(&h->rlock);
    while (h->inflight > 0)
        pthread_cond_wait(&h->rcond, &h->rlock);
    pthread_mutex_unlock(&h->rlock);
    detach_all(h);
    if (h->reg_id) {
        lock_fd = registry_lock();
        reg_fd = bpf_obj_get(REGISTRY_PIN);
        if (reg_fd >= 0) {
            bpf_map_delete_elem(reg_fd, &h->reg_id);
            close(reg_fd);
        }
        registry_unlock(lock_fd);
    }
    free_handle(h);
    return 0;
}

int ebpfdivert_shutdown(ebpfdivert_handle_t *h, int how)
{
    if (!h || (how & ~EBPFDIVERT_SHUTDOWN_BOTH) || !how)
        return -EINVAL;
    if (how & EBPFDIVERT_SHUTDOWN_RECV) {
        pthread_mutex_lock(&h->qlock);
        if (!h->shut_recv) {
            h->shut_recv = 1;
            pthread_mutex_lock(&h->cfg_lock);
            h->cfg.flags |= CFG_F_SHUTDOWN;
            h->evcfg.flags |= EVCFG_F_SHUTDOWN;
            pthread_mutex_unlock(&h->cfg_lock);
            if (h->cfg_fd >= 0)
                write_config(h);
        }
        wake_update(h);
        pthread_mutex_unlock(&h->qlock);
    }
    if (how & EBPFDIVERT_SHUTDOWN_SEND)
        __atomic_store_n(&h->shut_send, 1, __ATOMIC_RELEASE);
    return 0;
}

/*
 * After a RECV shutdown WinDivert still returns the packets already queued;
 * ebpfdivert_recv() returns -ESHUTDOWN only once the queue is empty.  The
 * next_entry() loop pops before checking shut_recv, which gives that order.
 */

static int ebpfdivert_set_param_impl(ebpfdivert_handle_t *h, int param, uint64_t value)
{
    if (!h)
        return -EINVAL;
    pthread_mutex_lock(&h->qlock);
    switch (param) {
    case EBPFDIVERT_PARAM_QUEUE_LENGTH:
        if (value < EBPFDIVERT_PARAM_QUEUE_LENGTH_MIN || value > EBPFDIVERT_PARAM_QUEUE_LENGTH_MAX)
            goto inval;
        h->queue_length = value;
        break;
    case EBPFDIVERT_PARAM_QUEUE_TIME:
        if (value < EBPFDIVERT_PARAM_QUEUE_TIME_MIN || value > EBPFDIVERT_PARAM_QUEUE_TIME_MAX)
            goto inval;
        h->queue_time = value;
        break;
    case EBPFDIVERT_PARAM_QUEUE_SIZE:
        if (value < EBPFDIVERT_PARAM_QUEUE_SIZE_MIN || value > EBPFDIVERT_PARAM_QUEUE_SIZE_MAX)
            goto inval;
        h->queue_size = value;
        break;
    default:
        goto inval;
    }
    pthread_mutex_unlock(&h->qlock);
    return 0;
inval:
    pthread_mutex_unlock(&h->qlock);
    return -EINVAL;
}

static int ebpfdivert_get_param_impl(ebpfdivert_handle_t *h, int param, uint64_t *value)
{
    if (!h || !value)
        return -EINVAL;
    switch (param) {
    case EBPFDIVERT_PARAM_QUEUE_LENGTH: *value = h->queue_length; return 0;
    case EBPFDIVERT_PARAM_QUEUE_TIME:   *value = h->queue_time;   return 0;
    case EBPFDIVERT_PARAM_QUEUE_SIZE:   *value = h->queue_size;   return 0;
    case EBPFDIVERT_PARAM_VERSION_MAJOR: *value = 2; return 0;
    case EBPFDIVERT_PARAM_VERSION_MINOR: *value = 2; return 0;
    default: return -EINVAL;
    }
}

int ebpfdivert_get_event_fd(ebpfdivert_handle_t *h)
{
    return h ? h->epfd : -EINVAL;
}

static int ebpfdivert_get_handle_stats_impl(ebpfdivert_handle_t *h, uint64_t *stats, int stats_len)
{
    int ncpu = libbpf_num_possible_cpus(), i, c;
    uint64_t *vals;
    if (!h || !stats || stats_len <= 0)
        return -EINVAL;
    if (ncpu <= 0)
        return ncpu ? ncpu : -EINVAL;
    vals = calloc((size_t)ncpu, sizeof(*vals));
    if (!vals)
        return -ENOMEM;
    for (i = 0; i < stats_len && i < STAT_MAX; i++) {
        uint32_t key = (uint32_t)i;
        stats[i] = 0;
        if (h->stats_fd >= 0 && bpf_map_lookup_elem(h->stats_fd, &key, vals) == 0)
            for (c = 0; c < ncpu; c++)
                stats[i] += vals[c];
    }
    free(vals);
    if (stats_len > STAT_QUEUE_FULL) {
        pthread_mutex_lock(&h->qlock);
        stats[STAT_QUEUE_FULL] += h->queue_drops;
        pthread_mutex_unlock(&h->qlock);
    }
    return i;
}

int ebpfdivert_unregister(void)
{
    int lock_fd = registry_lock(), reg_fd = bpf_obj_get(REGISTRY_PIN);
    if (reg_fd >= 0) {
        registry_reap(reg_fd);
        close(reg_fd);
    }
    registry_unlock(lock_fd);
    return 0;
}

/****************************************************************************/
/* Public entry points                                                      */
/****************************************************************************/

int ebpfdivert_recv(ebpfdivert_handle_t *h, void *pkt, uint32_t pkt_len, uint32_t *recv_len,
                    struct ebpfdivert_address *addr, int timeout_ms)
{
    if (!h)
        return -EINVAL;
    return GUARDED(h, ebpfdivert_recv_impl(h, pkt, pkt_len, recv_len, addr, timeout_ms));
}

int ebpfdivert_recv_ex(ebpfdivert_handle_t *h, void *pkt, uint32_t pkt_len, uint32_t *recv_len,
                       struct ebpfdivert_address *addrs, uint32_t *addr_len, int timeout_ms)
{
    if (!h)
        return -EINVAL;
    return GUARDED(h, ebpfdivert_recv_ex_impl(h, pkt, pkt_len, recv_len, addrs, addr_len, timeout_ms));
}

int ebpfdivert_send(ebpfdivert_handle_t *h, const void *pkt, uint32_t pkt_len, uint32_t *send_len,
                    const struct ebpfdivert_address *addr)
{
    if (!h)
        return -EINVAL;
    return GUARDED(h, ebpfdivert_send_impl(h, pkt, pkt_len, send_len, addr));
}

int ebpfdivert_send_ex(ebpfdivert_handle_t *h, const void *pkt, uint32_t pkt_len, uint32_t *send_len,
                       const struct ebpfdivert_address *addrs, uint32_t addr_len)
{
    if (!h)
        return -EINVAL;
    return GUARDED(h, ebpfdivert_send_ex_impl(h, pkt, pkt_len, send_len, addrs, addr_len));
}

int ebpfdivert_set_param(ebpfdivert_handle_t *h, int param, uint64_t value)
{
    if (!h)
        return -EINVAL;
    return GUARDED(h, ebpfdivert_set_param_impl(h, param, value));
}

int ebpfdivert_get_param(ebpfdivert_handle_t *h, int param, uint64_t *value)
{
    if (!h)
        return -EINVAL;
    return GUARDED(h, ebpfdivert_get_param_impl(h, param, value));
}

int ebpfdivert_get_handle_stats(ebpfdivert_handle_t *h, uint64_t *stats, int stats_len)
{
    if (!h)
        return -EINVAL;
    return GUARDED(h, ebpfdivert_get_handle_stats_impl(h, stats, stats_len));
}
