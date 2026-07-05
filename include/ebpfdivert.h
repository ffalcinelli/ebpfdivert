// SPDX-License-Identifier: GPL-2.0-or-later OR LGPL-3.0-or-later
#ifndef EBPFDIVERT_H
#define EBPFDIVERT_H

#define EBPFDIVERT_VERSION "0.0.4"

#include <stdint.h>
#include "ebpfdivert_shared.h"

#include <stdarg.h>

enum ebpfdivert_print_level {
    EBPFDIVERT_ERROR = 0,
    EBPFDIVERT_WARN  = 1,
    EBPFDIVERT_INFO  = 2,
    EBPFDIVERT_DEBUG = 3,
};

typedef int (*ebpfdivert_print_fn_t)(enum ebpfdivert_print_level level, const char *format, va_list args);
void ebpfdivert_set_print(ebpfdivert_print_fn_t print_fn);

#ifdef __cplusplus
extern "C" {
#endif

const char *ebpfdivert_version(void);

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

struct ebpfdivert_handle;
typedef struct ebpfdivert_handle ebpfdivert_handle_t;

/*
 * NOTE on Thread Safety:
 * ebpfdivert_handle_t handles are not thread-safe. Concurrently invoking ebpfdivert_recv
 * or ebpfdivert_send on the same handle across multiple threads without external
 * synchronization (e.g. mutex locking) will lead to race conditions or data corruption.
 */
ebpfdivert_handle_t *ebpfdivert_open(uint32_t priority);
int ebpfdivert_recv(ebpfdivert_handle_t *h, struct divert_packet_buffer *buf, size_t buf_len, int timeout_ms);
int ebpfdivert_send(ebpfdivert_handle_t *h, const struct divert_packet_buffer *buf);
int ebpfdivert_set_max_queue_size(ebpfdivert_handle_t *h, int size);
void ebpfdivert_close(ebpfdivert_handle_t *h);
int ebpfdivert_get_fd(ebpfdivert_handle_t *h);
int ebpfdivert_add_subnet_rule(ebpfdivert_handle_t *h, const char *ip_cidr, uint32_t action_mask);
int ebpfdivert_delete_subnet_rule(ebpfdivert_handle_t *h, const char *ip_cidr);

#ifdef __cplusplus
}
#endif

#endif // EBPFDIVERT_H

