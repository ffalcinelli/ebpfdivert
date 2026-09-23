// SPDX-License-Identifier: GPL-2.0-or-later OR LGPL-3.0-or-later
/*
 * Minimal POSIX stand-in for <windows.h>, just enough to compile the
 * vendored WinDivert helper sources (filter compiler, evaluator, packet
 * parser, checksums, hash) unmodified inside libebpfdivert.
 */
#ifndef EBPFDIVERT_WD_COMPAT_WINDOWS_H
#define EBPFDIVERT_WD_COMPAT_WINDOWS_H

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <limits.h>

#define __in
#define __in_opt
#define __out
#define __out_opt
#define __inout
#define __inout_opt

#define INT8    int8_t
#define UINT8   uint8_t
#define INT16   int16_t
#define UINT16  uint16_t
#define INT32   int32_t
#define UINT32  uint32_t
#define INT64   int64_t
#define UINT64  uint64_t

typedef void VOID;
typedef void *PVOID;
typedef void *LPVOID;
typedef void *HANDLE;
typedef void *LPOVERLAPPED;
typedef char CHAR;
typedef int INT;
typedef unsigned int UINT;
typedef int BOOL;
typedef uint8_t BOOLEAN;
typedef uint32_t DWORD;
typedef int64_t LONGLONG;
typedef size_t SIZE_T;
typedef union
{
    struct
    {
        uint32_t LowPart;
        uint32_t HighPart;
    };
    uint64_t QuadPart;
} ULARGE_INTEGER;

#ifndef TRUE
#define TRUE    1
#endif
#ifndef FALSE
#define FALSE   0
#endif

/* winsock provides these; the helper redefines them with identical values. */
#define IPPROTO_HOPOPTS     0
#define IPPROTO_ICMP        1
#define IPPROTO_TCP         6
#define IPPROTO_UDP         17
#define IPPROTO_ROUTING     43
#define IPPROTO_FRAGMENT    44
#define IPPROTO_AH          51
#define IPPROTO_ICMPV6      58
#define IPPROTO_NONE        59
#define IPPROTO_DSTOPTS     60

#define ERROR_SUCCESS               0
#define ERROR_INVALID_PARAMETER     87
#define ERROR_INSUFFICIENT_BUFFER   122

#define HEAP_NO_SERIALIZE           0x00000001
#define HEAP_ZERO_MEMORY            0x00000008

/* Implemented in wd_port.c. */
HANDLE HeapCreate(DWORD options, SIZE_T initial, SIZE_T maximum);
BOOL HeapDestroy(HANDLE heap);
LPVOID HeapAlloc(HANDLE heap, DWORD flags, SIZE_T size);
void SetLastError(DWORD err);
DWORD GetLastError(void);

#endif /* EBPFDIVERT_WD_COMPAT_WINDOWS_H */
