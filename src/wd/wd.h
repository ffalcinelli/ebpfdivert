// SPDX-License-Identifier: GPL-2.0-or-later OR LGPL-3.0-or-later
/*
 * Internal interface to the vendored WinDivert helper code (wd_port.c).
 *
 * Only plain C types appear here so that the rest of libebpfdivert can use
 * the filter compiler without pulling in the <windows.h> shim, whose
 * IPPROTO_* macros clash with <netinet/in.h>.  `addr` arguments point to an
 * 80-byte WINDIVERT_ADDRESS, i.e. a struct ebpfdivert_address.
 */
#ifndef EBPFDIVERT_WD_H
#define EBPFDIVERT_WD_H

#include <stdint.h>

#define WD_HIDDEN __attribute__((visibility("hidden")))

struct wd_filter;

/* Compile a filter string for a layer.  Returns 0 or -EINVAL/-ENOMEM. */
WD_HIDDEN int wd_filter_compile(const char *filter, int layer,
                                struct wd_filter **out,
                                const char **err_str, unsigned *err_pos);
WD_HIDDEN void wd_filter_free(struct wd_filter *f);

/* WINDIVERT_FILTER_FLAG_* summary of what the filter can match. */
WD_HIDDEN uint64_t wd_filter_flags(const struct wd_filter *f);
WD_HIDDEN int wd_filter_layer(const struct wd_filter *f);

/* Raw WINDIVERT_FILTER instructions (24 bytes each). */
WD_HIDDEN const void *wd_filter_object(const struct wd_filter *f,
                                       unsigned *len);

/* Serialized (WinDivertHelperCompileFilter) form, for REFLECT.  Returns
 * the length written including the NUL, or -errno. */
WD_HIDDEN int wd_filter_serialize(const struct wd_filter *f, char *buf,
                                  unsigned buflen);

/* 1 = match, 0 = no match, -EINVAL = malformed packet/address. */
WD_HIDDEN int wd_filter_eval(const struct wd_filter *f, const void *pkt,
                             unsigned pkt_len, const void *addr);

/* Wrappers of WinDivertHelper* functions.  Return 0 or -errno. */
WD_HIDDEN int wd_eval_filter_string(const char *filter, const void *pkt,
                                    unsigned pkt_len, const void *addr);
WD_HIDDEN int wd_format_filter(const char *filter, int layer, char *buf,
                               unsigned buflen);
WD_HIDDEN int wd_calc_checksums(void *pkt, unsigned pkt_len, void *addr,
                                uint64_t flags);
WD_HIDDEN uint64_t wd_hash_packet(const void *pkt, unsigned pkt_len,
                                  uint64_t seed);

/* Header offsets of a parsed IP packet (-1 when absent). */
struct wd_packet_info
{
    int ipv6;
    int fragment;
    uint8_t protocol;
    int ip_off;
    int transport_off;
    int payload_off;
    unsigned payload_len;
};
WD_HIDDEN int wd_parse_packet(const void *pkt, unsigned pkt_len,
                              struct wd_packet_info *info);

/* Report which checksums of the packet are currently valid. */
WD_HIDDEN void wd_verify_checksums(const void *pkt, unsigned pkt_len,
                                   int *ip_ok, int *tcp_ok, int *udp_ok);

#endif /* EBPFDIVERT_WD_H */
