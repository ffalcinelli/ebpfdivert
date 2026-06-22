// SPDX-License-Identifier: GPL-2.0-or-later OR LGPL-3.0-or-later
#ifndef EBPFDIVERT_H
#define EBPFDIVERT_H

#include <stdint.h>
#include "ebpfdivert_shared.h"

#ifdef __cplusplus
extern "C" {
#endif

int ebpfdivert_load(const char *ifname, const char *obj_path);
int ebpfdivert_unload(const char *ifname);
int ebpfdivert_rules_clear(void);
int ebpfdivert_rules_list(void);
int ebpfdivert_rules_add(int idx, const char *proto, const char *ip_cidr, const char *port_range, const char *action);
int ebpfdivert_get_stats(uint64_t *stats, int stats_len);

#ifdef __cplusplus
}
#endif

#endif // EBPFDIVERT_H
