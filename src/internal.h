// SPDX-License-Identifier: GPL-2.0-or-later OR LGPL-3.0-or-later
/* Internal helpers shared by the libebpfdivert translation units. */
#ifndef EBPFDIVERT_INTERNAL_H
#define EBPFDIVERT_INTERNAL_H

#include <stdint.h>
#include "ebpfdivert.h"

#define EBD_HIDDEN __attribute__((visibility("hidden")))

struct bpf_object;

EBD_HIDDEN int pr_log(enum ebpfdivert_print_level level, const char *format, ...)
    __attribute__((format(printf, 2, 3)));

/* Install the libbpf print hook and raise RLIMIT_MEMLOCK (old kernels). */
EBD_HIDDEN void ensure_libbpf_setup(void);

/* Open the BPF object embedded in the library; NULL + errno on failure. */
EBD_HIDDEN struct bpf_object *embedded_object_open(void);

/* Same for the FLOW/SOCKET object (ebpfdivert_events.bpf.c). */
EBD_HIDDEN struct bpf_object *embedded_events_object_open(void);

EBD_HIDDEN int getrandom_u64(uint64_t *out);

#endif /* EBPFDIVERT_INTERNAL_H */
