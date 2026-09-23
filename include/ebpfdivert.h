// SPDX-License-Identifier: GPL-2.0-or-later OR LGPL-3.0-or-later
#ifndef EBPFDIVERT_H
#define EBPFDIVERT_H

#define EBPFDIVERT_VERSION "0.1.0"

#include <stdint.h>
#include <stddef.h>
#include "ebpfdivert_shared.h"

#include <stdarg.h>

#ifdef __cplusplus
extern "C" {
#endif

enum ebpfdivert_print_level {
    EBPFDIVERT_ERROR = 0,
    EBPFDIVERT_WARN  = 1,
    EBPFDIVERT_INFO  = 2,
    EBPFDIVERT_DEBUG = 3,
};

typedef int (*ebpfdivert_print_fn_t)(enum ebpfdivert_print_level level, const char *format, va_list args);
void ebpfdivert_set_print(ebpfdivert_print_fn_t print_fn);

const char *ebpfdivert_version(void);

/****************************************************************************/
/* WinDivert-compatible handle API                                          */
/*                                                                          */
/* Layers, flags, params, events and the address layout are identical to   */
/* WinDivert 2.2, so bindings can share their Windows code paths.  Unless  */
/* stated otherwise functions return 0 (or a count) on success and a       */
/* negative errno on failure.                                               */
/****************************************************************************/

enum ebpfdivert_layer {
    EBPFDIVERT_LAYER_NETWORK         = 0,
    EBPFDIVERT_LAYER_NETWORK_FORWARD = 1,
    EBPFDIVERT_LAYER_FLOW            = 2,
    EBPFDIVERT_LAYER_SOCKET          = 3,
    EBPFDIVERT_LAYER_REFLECT         = 4,
};

enum ebpfdivert_event {
    EBPFDIVERT_EVENT_NETWORK_PACKET   = 0,
    EBPFDIVERT_EVENT_FLOW_ESTABLISHED = 1,
    EBPFDIVERT_EVENT_FLOW_DELETED     = 2,
    EBPFDIVERT_EVENT_SOCKET_BIND      = 3,
    EBPFDIVERT_EVENT_SOCKET_CONNECT   = 4,
    EBPFDIVERT_EVENT_SOCKET_LISTEN    = 5,
    EBPFDIVERT_EVENT_SOCKET_ACCEPT    = 6,
    EBPFDIVERT_EVENT_SOCKET_CLOSE     = 7,
    EBPFDIVERT_EVENT_REFLECT_OPEN     = 8,
    EBPFDIVERT_EVENT_REFLECT_CLOSE    = 9,
};

#define EBPFDIVERT_FLAG_SNIFF       0x0001
#define EBPFDIVERT_FLAG_DROP        0x0002
#define EBPFDIVERT_FLAG_RECV_ONLY   0x0004
#define EBPFDIVERT_FLAG_SEND_ONLY   0x0008
#define EBPFDIVERT_FLAG_NO_INSTALL  0x0010  /* accepted, no effect on Linux */
#define EBPFDIVERT_FLAG_FRAGMENTS   0x0020

enum ebpfdivert_param {
    EBPFDIVERT_PARAM_QUEUE_LENGTH  = 0,   /* packets */
    EBPFDIVERT_PARAM_QUEUE_TIME    = 1,   /* milliseconds */
    EBPFDIVERT_PARAM_QUEUE_SIZE    = 2,   /* bytes */
    EBPFDIVERT_PARAM_VERSION_MAJOR = 3,   /* WinDivert API level: 2 */
    EBPFDIVERT_PARAM_VERSION_MINOR = 4,   /* WinDivert API level: 2 */
};

#define EBPFDIVERT_PARAM_QUEUE_LENGTH_DEFAULT  4096
#define EBPFDIVERT_PARAM_QUEUE_LENGTH_MIN      32
#define EBPFDIVERT_PARAM_QUEUE_LENGTH_MAX      16384
#define EBPFDIVERT_PARAM_QUEUE_TIME_DEFAULT    2000
#define EBPFDIVERT_PARAM_QUEUE_TIME_MIN        100
#define EBPFDIVERT_PARAM_QUEUE_TIME_MAX        16000
#define EBPFDIVERT_PARAM_QUEUE_SIZE_DEFAULT    4194304
#define EBPFDIVERT_PARAM_QUEUE_SIZE_MIN        65535
#define EBPFDIVERT_PARAM_QUEUE_SIZE_MAX        33554432

enum ebpfdivert_shutdown_how {
    EBPFDIVERT_SHUTDOWN_RECV = 0x1,
    EBPFDIVERT_SHUTDOWN_SEND = 0x2,
    EBPFDIVERT_SHUTDOWN_BOTH = 0x3,
};

#define EBPFDIVERT_PRIORITY_HIGHEST  30000
#define EBPFDIVERT_PRIORITY_LOWEST   (-30000)
#define EBPFDIVERT_MTU_MAX           (40 + 0xFFFF)

/* Layer-specific data, laid out exactly like WINDIVERT_DATA_*. */
struct ebpfdivert_data_network {
    uint32_t if_idx;
    uint32_t sub_if_idx;
};

struct ebpfdivert_data_flow {
    uint64_t endpoint_id;
    uint64_t parent_endpoint_id;
    uint32_t process_id;
    uint32_t local_addr[4];     /* host order, word 0 least significant;  */
    uint32_t remote_addr[4];    /* IPv4 as ::ffff:a.b.c.d                 */
    uint16_t local_port;
    uint16_t remote_port;
    uint8_t  protocol;
};

struct ebpfdivert_data_socket {
    uint64_t endpoint_id;
    uint64_t parent_endpoint_id;
    uint32_t process_id;
    uint32_t local_addr[4];
    uint32_t remote_addr[4];
    uint16_t local_port;
    uint16_t remote_port;
    uint8_t  protocol;
};

struct ebpfdivert_data_reflect {
    int64_t  timestamp;
    uint32_t process_id;
    uint32_t layer;
    uint64_t flags;
    int16_t  priority;
};

/* Byte-identical to WINDIVERT_ADDRESS (80 bytes). */
struct ebpfdivert_address {
    int64_t  timestamp;             /* CLOCK_MONOTONIC nanoseconds */
    uint32_t layer:8;
    uint32_t event:8;
    uint32_t sniffed:1;
    uint32_t outbound:1;
    uint32_t loopback:1;
    uint32_t impostor:1;
    uint32_t ipv6:1;
    uint32_t ip_checksum:1;
    uint32_t tcp_checksum:1;
    uint32_t udp_checksum:1;
    uint32_t reserved1:8;
    uint32_t reserved2;
    union {
        struct ebpfdivert_data_network network;
        struct ebpfdivert_data_flow    flow;
        struct ebpfdivert_data_socket  socket;
        struct ebpfdivert_data_reflect reflect;
        uint8_t reserved3[64];
    };
};

struct ebpfdivert_handle;
typedef struct ebpfdivert_handle ebpfdivert_handle_t;

struct ebpfdivert_open_opts {
    size_t sz;                      /* sizeof(struct ebpfdivert_open_opts) */
    const char *const *ifnames;     /* NULL-terminated; NULL = all interfaces */
    uint32_t ring_bytes;            /* kernel ring buffer size, 0 = default */
};

/*
 * Open a handle.  priority follows WinDivert (-30000..30000, higher runs
 * first); 0 picks the next free position after existing handles.  Returns
 * NULL and sets errno on failure.  For a filter syntax error, errno is
 * EINVAL and ebpfdivert_helper_compile_filter() reports the position.
 */
ebpfdivert_handle_t *ebpfdivert_open(const char *filter, int layer, int16_t priority,
                                     uint64_t flags, const struct ebpfdivert_open_opts *opts);

/* Same as ebpfdivert_open(), for FFIs that cannot read errno: returns 0 and
 * stores the handle in *out, or a negative errno. */
int ebpfdivert_open_ex(const char *filter, int layer, int16_t priority, uint64_t flags,
                       const struct ebpfdivert_open_opts *opts, ebpfdivert_handle_t **out);

/*
 * Receive one packet (or event).  timeout_ms < 0 blocks, 0 polls.
 * Returns -EAGAIN on timeout, -ESHUTDOWN once shut down and drained,
 * -ENOBUFS if pkt is too small (the packet is dropped, recv_len set).
 */
int ebpfdivert_recv(ebpfdivert_handle_t *h, void *pkt, uint32_t pkt_len, uint32_t *recv_len,
                    struct ebpfdivert_address *addr, int timeout_ms);

/*
 * Receive up to *addr_len packets back-to-back into pkt.  On return
 * *addr_len is the number of packets and *recv_len the total bytes.  Waits
 * only for the first packet.
 */
int ebpfdivert_recv_ex(ebpfdivert_handle_t *h, void *pkt, uint32_t pkt_len, uint32_t *recv_len,
                       struct ebpfdivert_address *addrs, uint32_t *addr_len, int timeout_ms);

/* (Re-)inject a packet.  The address decides direction and interface. */
int ebpfdivert_send(ebpfdivert_handle_t *h, const void *pkt, uint32_t pkt_len, uint32_t *send_len,
                    const struct ebpfdivert_address *addr);

/* Inject addr_len packets stored back-to-back in pkt. */
int ebpfdivert_send_ex(ebpfdivert_handle_t *h, const void *pkt, uint32_t pkt_len, uint32_t *send_len,
                       const struct ebpfdivert_address *addrs, uint32_t addr_len);

int ebpfdivert_shutdown(ebpfdivert_handle_t *h, int how);
int ebpfdivert_close(ebpfdivert_handle_t *h);
int ebpfdivert_set_param(ebpfdivert_handle_t *h, int param, uint64_t value);
int ebpfdivert_get_param(ebpfdivert_handle_t *h, int param, uint64_t *value);

/* A file descriptor that becomes readable when ebpfdivert_recv() would not
 * block (for epoll/asyncio/selectors).  Owned by the handle. */
int ebpfdivert_get_event_fd(ebpfdivert_handle_t *h);

/* Kernel counters of this handle, indexed by STAT_*.  Returns the number
 * of counters written. */
int ebpfdivert_get_handle_stats(ebpfdivert_handle_t *h, uint64_t *stats, int stats_len);

/* Detach programs left behind by handles whose process died. */
int ebpfdivert_unregister(void);

/* Thread-safe description of a (positive or negative) errno value. */
const char *ebpfdivert_strerror(int err);

/****************************************************************************/
/* Helpers (WinDivertHelper* equivalents)                                   */
/****************************************************************************/

/* Check a filter.  On error returns -EINVAL and sets err_str and err_pos. */
int ebpfdivert_helper_compile_filter(const char *filter, int layer, const char **err_str,
                                     uint32_t *err_pos);
/* 1 = match, 0 = no match, <0 = error. */
int ebpfdivert_helper_eval_filter(const char *filter, const void *pkt, uint32_t pkt_len,
                                  const struct ebpfdivert_address *addr);
int ebpfdivert_helper_format_filter(const char *filter, int layer, char *buf, uint32_t buf_len);
/* flags: WINDIVERT_HELPER_NO_* (1 = IP, 2 = ICMP, 4 = ICMPv6, 8 = TCP, 16 = UDP). */
int ebpfdivert_helper_calc_checksums(void *pkt, uint32_t pkt_len, struct ebpfdivert_address *addr,
                                     uint64_t flags);
uint64_t ebpfdivert_helper_hash_packet(const void *pkt, uint32_t pkt_len, uint64_t seed);

/****************************************************************************/
/* Pinned global mode (ebpfdivert-cli load/rules)                           */
/****************************************************************************/

int ebpfdivert_load(const char *ifname, const char *obj_path, uint32_t priority);
int ebpfdivert_unload(const char *ifname);
int ebpfdivert_rules_clear(void);
int ebpfdivert_rules_list(void);
int ebpfdivert_rules_add(int idx, const char *proto, const char *ip_cidr, const char *port_range, const char *action);
int ebpfdivert_get_stats(uint64_t *stats, int stats_len);

struct ebpfdivert_rule_opt {
    const char *proto;
    const char *src_ip_cidr;
    const char *dst_ip_cidr;
    const char *src_port_range;
    const char *dst_port_range;
    const char *action;
    const char *direction;
    const char *loopback;
    const char *ttl;
    const char *tcp_flags;
    const char *tcp_flags_mask;
    uint16_t invert_mask;
};

int ebpfdivert_rules_add_extended(int idx, const struct ebpfdivert_rule_opt *opt);

#ifdef __cplusplus
}
#endif

#endif // EBPFDIVERT_H
