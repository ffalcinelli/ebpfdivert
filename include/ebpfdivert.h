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

struct ebpfdivert_handle;
typedef struct ebpfdivert_handle ebpfdivert_handle_t;

ebpfdivert_handle_t *ebpfdivert_open(uint32_t priority);
int ebpfdivert_recv(ebpfdivert_handle_t *h, struct divert_packet_buffer *buf, size_t buf_len, int timeout_ms);
int ebpfdivert_send(ebpfdivert_handle_t *h, const struct divert_packet_buffer *buf);
void ebpfdivert_close(ebpfdivert_handle_t *h);

#ifdef __cplusplus
}
#endif

#endif // EBPFDIVERT_H

