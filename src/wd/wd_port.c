// SPDX-License-Identifier: GPL-2.0-or-later OR LGPL-3.0-or-later
/*
 * wd_port.c - POSIX build of the vendored WinDivert helper API.
 *
 * This translation unit plays the role of windivert/dll/windivert.c: it
 * provides the prelude and the small utilities the helper sources expect,
 * then #includes windivert_shared.c and windivert_helper.c unmodified.
 * Everything here is internal to libebpfdivert (hidden visibility); the
 * public entry points are the ebpfdivert_helper_* wrappers in
 * ../ebpfdivert_helper.c.
 */
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>

#define WINDIVERTEXPORT extern __attribute__((visibility("hidden")))
#include "windivert.h"
#include "windivert_device.h"
#include "wd.h"

#pragma GCC diagnostic ignored "-Wunused-parameter"
#pragma GCC diagnostic ignored "-Wsign-compare"
#pragma GCC diagnostic ignored "-Wimplicit-fallthrough"
#pragma GCC diagnostic ignored "-Wmissing-field-initializers"
#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC diagnostic ignored "-Wmaybe-uninitialized"
#endif

/*
 * Win32 heap emulation: a pool is a linked list of allocations that is freed
 * as a whole by HeapDestroy.  The maximum size is honoured, since the filter
 * compiler relies on it to bound the complexity of filters.
 */
struct wd_heap_block
{
    struct wd_heap_block *next;
    max_align_t data[];
};

struct wd_heap
{
    struct wd_heap_block *blocks;
    size_t used;
    size_t maximum;
};

HANDLE HeapCreate(DWORD options, SIZE_T initial, SIZE_T maximum)
{
    struct wd_heap *heap = calloc(1, sizeof(*heap));
    (void)options;
    (void)initial;
    if (heap == NULL)
    {
        return NULL;
    }
    heap->maximum = maximum;
    return heap;
}

BOOL HeapDestroy(HANDLE handle)
{
    struct wd_heap *heap = handle;
    struct wd_heap_block *block, *next;
    if (heap == NULL)
    {
        return FALSE;
    }
    for (block = heap->blocks; block != NULL; block = next)
    {
        next = block->next;
        free(block);
    }
    free(heap);
    return TRUE;
}

LPVOID HeapAlloc(HANDLE handle, DWORD flags, SIZE_T size)
{
    struct wd_heap *heap = handle;
    struct wd_heap_block *block;
    if (heap == NULL || (heap->maximum != 0 && heap->used + size > heap->maximum))
    {
        SetLastError(ENOMEM);
        return NULL;
    }
    block = (flags & HEAP_ZERO_MEMORY) ? calloc(1, sizeof(*block) + size)
                                       : malloc(sizeof(*block) + size);
    if (block == NULL)
    {
        SetLastError(ENOMEM);
        return NULL;
    }
    block->next = heap->blocks;
    heap->blocks = block;
    heap->used += size;
    return block->data;
}

static __thread DWORD wd_last_error;

void SetLastError(DWORD err)
{
    wd_last_error = err;
}

DWORD GetLastError(void)
{
    return wd_last_error;
}

/*
 * Prelude copied from windivert/dll/windivert.c.
 */
static BOOLEAN WinDivertIsDigit(char c);
static BOOLEAN WinDivertIsXDigit(char c);
static BOOLEAN WinDivertIsSpace(char c);
static BOOLEAN WinDivertIsAlNum(char c);
static char WinDivertToLower(char c);
static int WinDivertStrCmp(const char *s, const char *t);
static BOOLEAN WinDivertAToI(const char *str, char **endptr, UINT32 *intptr,
    UINT size);
static BOOLEAN WinDivertAToX(const char *str, char **endptr, UINT32 *intptr,
    UINT size, BOOL prefix);
static UINT32 WinDivertDivTen128(UINT32 *a);

#define IPPROTO_MH      135

#define WINDIVERT_INLINE    __attribute__((__always_inline__)) inline

static BOOL WinDivertGetData(const VOID *packet, UINT packet_len, INT min,
    INT max, INT idx, PVOID data, UINT size);
#define WINDIVERT_GET_DATA(packet, packet_len, min, max, index, data, size) \
    WinDivertGetData((packet), (packet_len), (min), (max), (index), (data), \
        (size))

#include "windivert_shared.c"
#include "windivert_helper.c"

/*
 * Utilities copied from windivert/dll/windivert.c.
 */
static BOOLEAN WinDivertIsDigit(char c)
{
    return (c >= '0' && c <= '9');
}

static BOOLEAN WinDivertIsXDigit(char c)
{
    return (c >= '0' && c <= '9') ||
           (c >= 'a' && c <= 'f') ||
           (c >= 'A' && c <= 'F');
}

static BOOLEAN WinDivertIsSpace(char c)
{
    return (c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f' ||
            c == '\v');
}

static BOOLEAN WinDivertIsAlNum(char c)
{
    return (c >= 'a' && c <= 'z') ||
           (c >= 'A' && c <= 'Z') ||
           (c >= '0' && c <= '9');
}

static char WinDivertToLower(char c)
{
    if (c >= 'A' && c <= 'Z')
        return 'a' + (c - 'A');
    return c;
}

static int WinDivertStrCmp(const char *s, const char *t)
{
    int cmp;
    size_t i;
    for (i = 0; ; i++)
    {
        cmp = s[i] - t[i];
        if (cmp != 0)
        {
            return cmp;
        }
        if (s[i] == '\0')
        {
            return 0;
        }
    }
}

static BOOLEAN WinDivertMul128(UINT32 *n, UINT32 m)
{
    UINT64 n64 = (UINT64)n[0] * (UINT64)m;
    n[0] = (UINT32)n64;
    n64 = (UINT64)n[1] * (UINT64)m + (n64 >> 32);
    n[1] = (UINT32)n64;
    n64 = (UINT64)n[2] * (UINT64)m + (n64 >> 32);
    n[2] = (UINT32)n64;
    n64 = (UINT64)n[3] * (UINT64)m + (n64 >> 32);
    n[3] = (UINT32)n64;
    return ((n64 >> 32) == 0);
}

static BOOLEAN WinDivertAdd128(UINT32 *n, UINT32 a)
{
    UINT64 n64 = (UINT64)n[0] + (UINT64)a;
    n[0] = (UINT32)n64;
    n64 = (UINT64)n[1] + (n64 >> 32);
    n[1] = (UINT32)n64;
    n64 = (UINT64)n[2] + (n64 >> 32);
    n[2] = (UINT32)n64;
    n64 = (UINT64)n[3] + (n64 >> 32);
    n[3] = (UINT32)n64;
    return ((n64 >> 32) == 0);
}

static BOOLEAN WinDivertAToI(const char *str, char **endptr, UINT32 *intptr,
    UINT size)
{
    size_t i = 0;
    UINT32 n[4] = {0};
    BOOLEAN result = TRUE;
    for (; str[i] && WinDivertIsDigit(str[i]); i++)
    {
        if (!WinDivertMul128(n, 10) || !WinDivertAdd128(n, str[i] - '0'))
        {
            return FALSE;
        }
    }
    if (i == 0)
    {
        return FALSE;
    }
    if (endptr != NULL)
    {
        *endptr = (char *)str + i;
    }
    for (i = 0; i < size; i++)
    {
        intptr[i] = n[i];
    }
    for (; result && i < size && i < 4; i++)
    {
        result = result && (n[i] == 0);
    }
    return result;
}

static BOOLEAN WinDivertAToX(const char *str, char **endptr, UINT32 *intptr,
    UINT size, BOOL prefix)
{
    size_t i = 0;
    UINT32 n[4] = {0}, dig;
    BOOLEAN result = TRUE;
    if (prefix)
    {
        if (str[i] == '0' && str[i+1] == 'x')
        {
            i += 2;
        }
        else
        {
            return FALSE;
        }
    }
    for (; str[i] && WinDivertIsXDigit(str[i]); i++)
    {
        if (WinDivertIsDigit(str[i]))
        {
            dig = (UINT32)(str[i] - '0');
        }
        else
        {
            dig = (UINT32)(WinDivertToLower(str[i]) - 'a') + 0x0A;
        }
        if (!WinDivertMul128(n, 16) || !WinDivertAdd128(n, dig))
        {
            return FALSE;
        }
    }
    if (i == 0)
    {
        return FALSE;
    }
    if (endptr != NULL)
    {
        *endptr = (char *)str + i;
    }
    for (i = 0; i < size; i++)
    {
        intptr[i] = n[i];
    }
    for (; result && i < size && i < 4; i++)
    {
        result = result && (n[i] == 0);
    }
    return result;
}

/*
 * Divide by 10 and return the remainder.
 */
#define WINDIVERT_BIG_MUL_ROUND(a, c, r, i)                                 \
    do {                                                                    \
        UINT64 t = WINDIVERT_MUL64((UINT64)(a), (UINT64)(c));               \
        UINT k;                                                             \
        for (k = (i); k < 9 && t != 0; k++)                                 \
        {                                                                   \
            UINT64 s = (UINT64)(r)[k] + (t & 0xFFFFFFFF);                   \
            (r)[k] = (UINT32)s;                                             \
            t = (t >> 32) + (s >> 32);                                      \
        }                                                                   \
    } while (FALSE)
static UINT32 WinDivertDivTen128(UINT32 *a)
{
    const UINT32 c[5] =
    {
        0x9999999A, 0x99999999, 0x99999999, 0x99999999, 0x19999999
    };
    UINT32 r[9] = {0}, m[6] = {0};
    UINT i, j;

    for (i = 0; i < 4; i++)
    {
        for (j = 0; j < 5; j++)
        {
            WINDIVERT_BIG_MUL_ROUND(a[i], c[j], r, i+j);
        }
    }

    a[0] = r[5];
    a[1] = r[6];
    a[2] = r[7];
    a[3] = r[8];
    
    for (i = 0; i < 5; i++)
    {
        WINDIVERT_BIG_MUL_ROUND(r[i], 10, m, i);
    }
    
    return m[5];
}


/****************************************************************************/
/* libebpfdivert internal interface (wd.h)                                  */
/****************************************************************************/

_Static_assert(sizeof(WINDIVERT_ADDRESS) == 80, "WINDIVERT_ADDRESS size");
_Static_assert(sizeof(WINDIVERT_FILTER) == 24, "WINDIVERT_FILTER size");

struct wd_filter
{
    int layer;
    UINT length;
    UINT64 flags;
    WINDIVERT_FILTER object[WINDIVERT_FILTER_MAXLEN];
};

static int wd_errno(void)
{
    DWORD err = GetLastError();
    switch (err)
    {
        case ERROR_SUCCESS:
        case ERROR_INVALID_PARAMETER:
            return -EINVAL;
        case ERROR_INSUFFICIENT_BUFFER:
            return -ENOSPC;
        default:
            return -(int)err;
    }
}

int wd_filter_compile(const char *filter, int layer, struct wd_filter **out,
    const char **err_str, unsigned *err_pos)
{
    struct wd_filter *f;
    HANDLE pool;
    ERROR err;

    if (err_str != NULL)
    {
        *err_str = NULL;
    }
    if (err_pos != NULL)
    {
        *err_pos = 0;
    }
    if (filter == NULL || out == NULL || layer < WINDIVERT_LAYER_NETWORK ||
        layer > WINDIVERT_LAYER_MAX)
    {
        return -EINVAL;
    }
    f = calloc(1, sizeof(*f));
    if (f == NULL)
    {
        return -ENOMEM;
    }
    pool = HeapCreate(HEAP_NO_SERIALIZE, WINDIVERT_MIN_POOL_SIZE,
        WINDIVERT_MAX_POOL_SIZE);
    if (pool == NULL)
    {
        free(f);
        return -ENOMEM;
    }
    err = WinDivertCompileFilter(filter, pool, (WINDIVERT_LAYER)layer,
        f->object, &f->length);
    HeapDestroy(pool);
    if (IS_ERROR(err))
    {
        if (err_str != NULL)
        {
            *err_str = WinDivertErrorString(GET_CODE(err));
        }
        if (err_pos != NULL)
        {
            *err_pos = GET_POS(err);
        }
        free(f);
        return (GET_CODE(err) == WINDIVERT_ERROR_NO_MEMORY? -ENOMEM: -EINVAL);
    }
    f->layer = layer;
    f->flags = WinDivertAnalyzeFilter((WINDIVERT_LAYER)layer, f->object,
        f->length);
    *out = f;
    return 0;
}

void wd_filter_free(struct wd_filter *f)
{
    free(f);
}

uint64_t wd_filter_flags(const struct wd_filter *f)
{
    return f->flags;
}

int wd_filter_layer(const struct wd_filter *f)
{
    return f->layer;
}

const void *wd_filter_object(const struct wd_filter *f, unsigned *len)
{
    if (len != NULL)
    {
        *len = f->length;
    }
    return f->object;
}

int wd_filter_serialize(const struct wd_filter *f, char *buf, unsigned buflen)
{
    WINDIVERT_STREAM stream;
    stream.data     = buf;
    stream.pos      = 0;
    stream.max      = buflen;
    stream.overflow = FALSE;
    WinDivertSerializeFilter(&stream, f->object, f->length);
    if (stream.overflow)
    {
        return -ENOSPC;
    }
    return (int)stream.pos;
}

int wd_filter_eval(const struct wd_filter *f, const void *packet,
    unsigned packet_len, const void *addr0)
{
    const WINDIVERT_ADDRESS *addr = addr0;
    WINDIVERT_PACKET info;
    const WINDIVERT_DATA_NETWORK *network_data = NULL;
    const WINDIVERT_DATA_FLOW *flow_data = NULL;
    const WINDIVERT_DATA_SOCKET *socket_data = NULL;
    const WINDIVERT_DATA_REFLECT *reflect_data = NULL;
    int result;

    memset(&info, 0, sizeof(info));
    if (f == NULL || addr == NULL || addr->Layer != (UINT32)f->layer)
    {
        return -EINVAL;
    }
    switch (addr->Layer)
    {
        case WINDIVERT_LAYER_NETWORK:
        case WINDIVERT_LAYER_NETWORK_FORWARD:
            if (packet == NULL ||
                !WinDivertHelperParsePacketEx((PVOID)packet, packet_len,
                    &info))
            {
                return -EINVAL;
            }
            if ((addr->IPv6 && info.IPv6Header == NULL) ||
                (!addr->IPv6 && info.IPHeader == NULL))
            {
                return -EINVAL;
            }
            network_data = &addr->Network;
            break;
        case WINDIVERT_LAYER_FLOW:
            flow_data = &addr->Flow;
            break;
        case WINDIVERT_LAYER_SOCKET:
            socket_data = &addr->Socket;
            break;
        case WINDIVERT_LAYER_REFLECT:
            reflect_data = &addr->Reflect;
            break;
        default:
            return -EINVAL;
    }

    result = WinDivertExecuteFilter(
        f->object,
        addr->Layer,
        addr->Timestamp,
        addr->Event,
        (addr->IPv6 != 0? FALSE: TRUE),
        (addr->Outbound != 0? TRUE: FALSE),
        (addr->Loopback != 0? TRUE: FALSE),
        (addr->Impostor != 0? TRUE: FALSE),
        info.Fragment,
        network_data,
        flow_data,
        socket_data,
        reflect_data,
        info.IPHeader,
        info.IPv6Header,
        info.ICMPHeader,
        info.ICMPv6Header,
        info.TCPHeader,
        info.UDPHeader,
        info.Protocol,
        packet,
        packet_len,
        info.HeaderLength,
        info.PayloadLength);
    if (result < 0)
    {
        return -EINVAL;
    }
    return (result != 0);
}

int wd_eval_filter_string(const char *filter, const void *packet,
    unsigned packet_len, const void *addr)
{
    SetLastError(ERROR_SUCCESS);
    if (WinDivertHelperEvalFilter(filter, packet, packet_len, addr))
    {
        return 1;
    }
    return (GetLastError() == ERROR_SUCCESS? 0: wd_errno());
}

int wd_format_filter(const char *filter, int layer, char *buf,
    unsigned buflen)
{
    if (!WinDivertHelperFormatFilter(filter, (WINDIVERT_LAYER)layer, buf,
            buflen))
    {
        return wd_errno();
    }
    return 0;
}

int wd_calc_checksums(void *packet, unsigned packet_len, void *addr,
    uint64_t flags)
{
    if (!WinDivertHelperCalcChecksums(packet, packet_len, addr, flags))
    {
        return wd_errno();
    }
    return 0;
}

uint64_t wd_hash_packet(const void *packet, unsigned packet_len,
    uint64_t seed)
{
    return WinDivertHelperHashPacket(packet, packet_len, seed);
}

int wd_parse_packet(const void *packet, unsigned packet_len,
    struct wd_packet_info *out)
{
    WINDIVERT_PACKET info;
    const UINT8 *base = packet;

    if (!WinDivertHelperParsePacketEx((PVOID)packet, packet_len, &info))
    {
        return -EINVAL;
    }
    out->ipv6 = (info.IPv6Header != NULL);
    out->fragment = info.Fragment;
    out->protocol = info.Protocol;
    out->ip_off = (info.IPHeader != NULL? (int)((UINT8 *)info.IPHeader - base):
        info.IPv6Header != NULL? (int)((UINT8 *)info.IPv6Header - base): -1);
    out->transport_off =
        info.TCPHeader != NULL? (int)((UINT8 *)info.TCPHeader - base):
        info.UDPHeader != NULL? (int)((UINT8 *)info.UDPHeader - base):
        info.ICMPHeader != NULL? (int)((UINT8 *)info.ICMPHeader - base):
        info.ICMPv6Header != NULL? (int)((UINT8 *)info.ICMPv6Header - base):
        -1;
    out->payload_off = (info.Payload != NULL?
        (int)(info.Payload - base): -1);
    out->payload_len = info.PayloadLength;
    return 0;
}

void wd_verify_checksums(const void *packet, unsigned packet_len,
    int *ip_ok, int *tcp_ok, int *udp_ok)
{
    WINDIVERT_PACKET info;
    UINT8 *copy;
    UINT16 old_sum;

    *ip_ok = *tcp_ok = *udp_ok = 0;
    if (!WinDivertHelperParsePacketEx((PVOID)packet, packet_len, &info) ||
        info.Fragment || info.Truncated)
    {
        return;
    }
    copy = malloc(packet_len);
    if (copy == NULL)
    {
        return;
    }
    memcpy(copy, packet, packet_len);
    WinDivertHelperCalcChecksums(copy, packet_len, NULL, 0);
    if (info.IPHeader != NULL)
    {
        size_t off = (UINT8 *)&info.IPHeader->Checksum - (UINT8 *)packet;
        memcpy(&old_sum, copy + off, sizeof(old_sum));
        *ip_ok = (old_sum == info.IPHeader->Checksum);
    }
    if (info.TCPHeader != NULL)
    {
        size_t off = (UINT8 *)&info.TCPHeader->Checksum - (UINT8 *)packet;
        memcpy(&old_sum, copy + off, sizeof(old_sum));
        *tcp_ok = (old_sum == info.TCPHeader->Checksum);
    }
    if (info.UDPHeader != NULL)
    {
        size_t off = (UINT8 *)&info.UDPHeader->Checksum - (UINT8 *)packet;
        memcpy(&old_sum, copy + off, sizeof(old_sum));
        *udp_ok = (old_sum == info.UDPHeader->Checksum);
    }
    free(copy);
}
