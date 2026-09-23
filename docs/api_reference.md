# eBPFDivert C API reference

`#include <ebpfdivert/ebpfdivert.h>`, link with `-lebpfdivert` (SONAME `libebpfdivert.so.0`).

The API mirrors WinDivert 2.2. Layers, events, flags, parameters, the filter language and the address layout
are identical, so a WinDivert program ports by renaming `WinDivert*` to `ebpfdivert_*`. The differences
are listed at the end.

Unless stated otherwise, functions return `0` (or a count) on success and a **negative errno** on failure.
`ebpfdivert_strerror(err)` describes any errno value (positive or negative) and is thread-safe.

## Handles

### `ebpfdivert_open` / `ebpfdivert_open_ex`

```c
ebpfdivert_handle_t *ebpfdivert_open(const char *filter, int layer, int16_t priority,
                                     uint64_t flags, const struct ebpfdivert_open_opts *opts);
int ebpfdivert_open_ex(const char *filter, int layer, int16_t priority, uint64_t flags,
                       const struct ebpfdivert_open_opts *opts, ebpfdivert_handle_t **out);
```

These open a handle, like `WinDivertOpen`. `ebpfdivert_open` returns `NULL` and sets `errno`. `_ex` returns the
negative errno, for FFIs that cannot read `errno`.

- **`filter`**: a WinDivert filter string.
- **`layer`**: `EBPFDIVERT_LAYER_NETWORK` (0), `NETWORK_FORWARD` (1), `FLOW` (2), `SOCKET` (3) or `REFLECT` (4).
- **`priority`**: from -30000 to 30000. Higher values see packets first. `0` places the handle after every
  existing handle.
- **`flags`**:

  | Flag | Value | Notes |
  | --- | --- | --- |
  | `SNIFF` | `0x01` | Receive copies; packets continue. Required with `RECV_ONLY` on FLOW and REFLECT. |
  | `DROP` | `0x02` | Drop matching packets without receiving them. |
  | `RECV_ONLY` | `0x04` | Required on SOCKET, FLOW and REFLECT. |
  | `SEND_ONLY` | `0x08` | Inject only; nothing is attached. |
  | `NO_INSTALL` | `0x10` | Accepted; there is nothing to install on Linux. |
  | `FRAGMENTS` | `0x20` | Also capture inbound IP fragments. |

- **`opts`**: optional (`NULL` for defaults).

  ```c
  struct ebpfdivert_open_opts {
      size_t sz;                  /* sizeof(struct ebpfdivert_open_opts) */
      const char *const *ifnames; /* NULL-terminated interface list; NULL = all (lo is always included) */
      uint32_t ring_bytes;        /* kernel ring buffer size, 0 = default (8 MB) */
  };
  ```

Errors:

| errno | Meaning |
| --- | --- |
| `EINVAL` | Bad filter, layer, priority or flag combination. For a bad filter, `ebpfdivert_helper_compile_filter()` gives the message and position. |
| `EPERM` | Missing `CAP_BPF`/`CAP_NET_ADMIN`. |
| `EOPNOTSUPP` | The kernel lacks a needed feature (cgroup v2 for event layers), or a SOCKET filter without `SNIFF` that cannot be enforced (see below). |
| `ENODEV` | An interface in `ifnames` does not exist. |

### `ebpfdivert_recv` / `ebpfdivert_recv_ex`

```c
int ebpfdivert_recv(ebpfdivert_handle_t *h, void *pkt, uint32_t pkt_len, uint32_t *recv_len,
                    struct ebpfdivert_address *addr, int timeout_ms);
int ebpfdivert_recv_ex(ebpfdivert_handle_t *h, void *pkt, uint32_t pkt_len, uint32_t *recv_len,
                       struct ebpfdivert_address *addrs, uint32_t *addr_len, int timeout_ms);
```

`recv` receives one packet, or one event (which has 0 bytes, or the filter object for REFLECT).

- **`timeout_ms`**: `< 0` blocks, `0` polls.
- A buffer of `EBPFDIVERT_MTU_MAX` bytes always fits a packet, including GSO aggregates.

It returns:

| Return | Meaning |
| --- | --- |
| `-EAGAIN` | Timeout. |
| `-ESHUTDOWN` | The handle was shut down (or closed) and the queue is drained. |
| `-ENOBUFS` | `pkt` is too small. The packet is dropped, and `*recv_len` holds its size. |

`recv_ex` receives up to `*addr_len` packets back to back. It waits only for the first one, then sets `*addr_len`
and `*recv_len`.

### `ebpfdivert_send` / `ebpfdivert_send_ex`

```c
int ebpfdivert_send(ebpfdivert_handle_t *h, const void *pkt, uint32_t pkt_len, uint32_t *send_len,
                    const struct ebpfdivert_address *addr);
int ebpfdivert_send_ex(ebpfdivert_handle_t *h, const void *pkt, uint32_t pkt_len, uint32_t *send_len,
                       const struct ebpfdivert_address *addrs, uint32_t addr_len);
```

These inject an IPv4 or IPv6 packet.

- **Direction and interface.** `addr.outbound`, `addr.loopback` and `addr.network.if_idx` decide both.
- **Checksums.** A cleared `ip_checksum`/`tcp_checksum`/`udp_checksum` flag means "recalculate".
- **Round trip.** Pass the address received with the packet unchanged (all 80 bytes). It carries the capture
  context needed to re-inject the packet where it was stolen.
- **Priority.** Injected packets are skipped by this handle and by higher-priority ones. Lower-priority
  handles see them as `impostor`.

`send_ex` sends `addr_len` packets stored back to back.

### Other handle calls

```c
int ebpfdivert_shutdown(ebpfdivert_handle_t *h, int how);   /* EBPFDIVERT_SHUTDOWN_RECV / SEND / BOTH */
int ebpfdivert_close(ebpfdivert_handle_t *h);
int ebpfdivert_set_param(ebpfdivert_handle_t *h, int param, uint64_t value);
int ebpfdivert_get_param(ebpfdivert_handle_t *h, int param, uint64_t *value);
int ebpfdivert_get_event_fd(ebpfdivert_handle_t *h);
int ebpfdivert_get_handle_stats(ebpfdivert_handle_t *h, uint64_t *stats, int stats_len);
int ebpfdivert_unregister(void);
```

- **`shutdown`**
  - `RECV` makes the kernel pass everything. `recv` still returns the packets already queued, then
    `-ESHUTDOWN`.
  - `SEND` makes further sends fail with `-ESHUTDOWN`.
- **`close`** detaches the programs and wakes blocked receivers. It waits for calls in progress on other
  threads.
- **Parameters**:

  | Param | Default | Range |
  | --- | --- | --- |
  | `QUEUE_LENGTH` (0), packets | 4096 | 32–16384 |
  | `QUEUE_TIME` (1), ms | 2000 | 100–16000 |
  | `QUEUE_SIZE` (2), bytes | 4 MB | 64 KB–32 MB |
  | `VERSION_MAJOR` / `VERSION_MINOR` (3/4) | 2 / 2 | read-only |

- **`get_event_fd`** returns a descriptor owned by the handle. It is readable whenever `recv` would not block,
  for use with `epoll`, asyncio `add_reader` or selectors.
- **`get_handle_stats`** fills the counters indexed by `STAT_*`:
  - `DIVERTED`, `DROPPED`, `SNIFFED`
  - `PARSING_ERR`
  - `RINGBUF_FULL`, `QUEUE_FULL`
  - `TOO_BIG`, `OWNER_GONE`

  It returns the number of counters written.
- **`unregister`** reaps the registry entries and TC filters of dead processes. Live handles are untouched.

## The address

`struct ebpfdivert_address` is byte-identical to `WINDIVERT_ADDRESS` (80 bytes).

- **Header fields.** The first 16 bytes hold the following:
  - `timestamp`: `CLOCK_MONOTONIC` nanoseconds.
  - `layer` and `event`.
  - `sniffed`, `outbound`, `loopback`, `impostor` and `ipv6`.
  - Three checksum flags.
- **Union.** The remaining 64 bytes are a union of `network` (`if_idx`, `sub_if_idx`), `flow`, `socket`
  (`endpoint_id`, `parent_endpoint_id`, `process_id`, `local_addr[4]`, `remote_addr[4]`, ports, `protocol`)
  and `reflect` (`timestamp`, `process_id`, `layer`, `flags`, `priority`).
  - Event addresses are in host order, with IPv4 mapped to `::ffff:a.b.c.d`, as in WinDivert.
  - For network packets, bytes 16–63 of the union hold opaque capture context.

## Helpers

```c
int ebpfdivert_helper_compile_filter(const char *filter, int layer, const char **err_str, uint32_t *err_pos);
int ebpfdivert_helper_eval_filter(const char *filter, const void *pkt, uint32_t pkt_len,
                                  const struct ebpfdivert_address *addr);            /* 1, 0 or -errno */
int ebpfdivert_helper_format_filter(const char *filter, int layer, char *buf, uint32_t buf_len);
int ebpfdivert_helper_calc_checksums(void *pkt, uint32_t pkt_len, struct ebpfdivert_address *addr,
                                     uint64_t flags);
uint64_t ebpfdivert_helper_hash_packet(const void *pkt, uint32_t pkt_len, uint64_t seed);
```

These are `WinDivertHelperCompileFilter`, `EvalFilter`, `FormatFilter`, `CalcChecksums` and `HashPacket`, running
WinDivert's own code. None of them needs privileges.

## Logging and version

```c
typedef int (*ebpfdivert_print_fn_t)(enum ebpfdivert_print_level level, const char *fmt, va_list args);
void ebpfdivert_set_print(ebpfdivert_print_fn_t fn);   /* also receives libbpf output; NULL silences */
const char *ebpfdivert_version(void);                  /* "0.1.0" */
```

## Differences from WinDivert

- **SOCKET blocking.** Without `SNIFF`, only BIND and CONNECT can be refused. The filter must be exact on
  event, protocol, local/remote address and port, and process ID. Filters that could match LISTEN or ACCEPT,
  or use other fields, fail with `EOPNOTSUPP`. CLOSE events are never blocked.
- **`sub_if_idx`** is always 0.
- **Timestamps** are `CLOCK_MONOTONIC` nanoseconds, not `QueryPerformanceCounter` ticks.
- **Loopback on NETWORK_FORWARD.** Forwarded packets never have `loopback` set.

## Pinned global mode

`ebpfdivert_load`, `unload`, `rules_*`, `rules_add_extended` and `get_stats` drive a single shared program with
maps pinned under `/sys/fs/bpf/ebpfdivert/`. They are used by `ebpfdivert-cli load/rules/stats`. This mode is
independent of handles and is described in [rules_reference.md](rules_reference.md).
