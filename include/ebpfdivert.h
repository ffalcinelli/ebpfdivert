// SPDX-License-Identifier: GPL-2.0-or-later OR LGPL-3.0-or-later
#ifndef EBPFDIVERT_H
#define EBPFDIVERT_H

#include <stdint.h>
#include "ebpfdivert_shared.h"

#ifdef __cplusplus
extern "C" {
#endif

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

#ifdef __cplusplus
}
#endif

#endif // EBPFDIVERT_H

