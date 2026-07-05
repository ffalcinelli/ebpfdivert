# eBPFDivert C API Reference

The user-space shared library `libebpfdivert.so` exposes a C interface to control the loader, manage filtering rules, and capture or inject packets.

---

## 1. Driver Lifecycle Management

### `ebpfdivert_load`
```c
int ebpfdivert_load(const char *ifname, const char *obj_path, uint32_t priority);
```
Loads the compiled BPF classifier object and attaches it to the Traffic Control (TC) ingress and egress hooks on the specified interface.
- **`ifname`**: The interface name (e.g. `"eth0"`), or `"all"` / `NULL` to attach to all interfaces.
- **`obj_path`**: Path to the compiled `ebpfdivert.bpf.o` object file.
- **`priority`**: Loader priority. Sets the default priority for this driver instance.
- **Returns**: `0` on success, or a negative value on failure.

### `ebpfdivert_unload`
```c
int ebpfdivert_unload(const char *ifname);
```
Unloads the driver by removing the eBPFDivert TC hooks and filters from the interface.
- **`ifname`**: Interface name, or `"all"` / `NULL` to detach from all interfaces.
- **Returns**: `0` on success, or a negative value on failure.

---

## 2. Rule Management

### `ebpfdivert_rules_clear`
```c
int ebpfdivert_rules_clear(void);
```
Clears all rule entries in both the IPv4 and IPv6 rules maps.
- **Returns**: `0` on success, or a negative value on failure.

### `ebpfdivert_rules_add`
```c
int ebpfdivert_rules_add(int idx, const char *proto, const char *ip_cidr, const char *port_range, const char *action);
```
Adds a basic destination-matching rule.
- **`idx`**: Rule index (0 to 63).
- **`proto`**: Protocol string (`"tcp"`, `"udp"`, `"icmp"`, `"icmpv6"`, or `"any"`).
- **`ip_cidr`**: Destination IP range in CIDR notation (e.g. `"192.168.1.0/24"`, `"fe80::/10"`, or `"any"`).
- **`port_range`**: Destination port (e.g. `"80"`), port range (`"1000-2000"`), ICMP type/code (`"8/0"`), or `"any"`.
- **`action`**: Action string (`"divert"`, `"drop"`, or `"sniff"`).

### `ebpfdivert_rules_add_extended`
```c
int ebpfdivert_rules_add_extended(int idx, const struct ebpfdivert_rule_opt *opt);
```
Adds an advanced filtering rule using options defined in `struct ebpfdivert_rule_opt`:
```c
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
```

---

## 3. Data Flow & Queueing

### `ebpfdivert_open`
```c
ebpfdivert_handle_t *ebpfdivert_open(uint32_t priority);
```
Creates and opens a new capture handle. Connects to the pinned BPF ring buffer.
- **`priority`**: The priority associated with this capture handle. Used in loop prevention.
- **Returns**: Pointer to the opened handle, or `NULL` on failure.

### `ebpfdivert_recv`
```c
int ebpfdivert_recv(ebpfdivert_handle_t *h, struct divert_packet_buffer *buf, size_t buf_len, int timeout_ms);
```
Captures a diverted packet from the BPF ring buffer or the internal cache queue.
- **`h`**: The capture handle.
- **`buf`**: Pointer to the buffer structure where the packet will be written.
- **`buf_len`**: Size of the buffer structure.
- **`timeout_ms`**: Timeout in milliseconds to block waiting for packets (`-1` to block indefinitely).
- **Returns**: `0` on success, `-EAGAIN` if the timeout expired without receiving a packet, or another negative error code.

### `ebpfdivert_send`
```c
int ebpfdivert_send(ebpfdivert_handle_t *h, const struct divert_packet_buffer *buf);
```
Re-injects a packet back into the network stack. Uses interface-specific raw sockets cached within the handle.
- **`h`**: The capture handle.
- **`buf`**: The packet buffer structure to send.
- **Returns**: `0` on success, or a negative error code on failure.

### `ebpfdivert_set_max_queue_size`
```c
int ebpfdivert_set_max_queue_size(ebpfdivert_handle_t *h, int size);
```
Sets the maximum size of the user-space FIFO queue used to cache packets under burst arrivals.
- **`size`**: Maximum number of packets (default: `1024`).

### `ebpfdivert_close`
```c
void ebpfdivert_close(ebpfdivert_handle_t *h);
```
Closes the capture handle, releases cached raw sockets, and frees the internal packet queue.

---

## 4. Telemetry & Custom Logging

### `ebpfdivert_get_stats`
```c
int ebpfdivert_get_stats(uint64_t *stats, int stats_len);
```
Retrieves the real-time packet processing telemetry statistics.
- **`stats`**: Pointer to a `uint64_t` array where stats will be written.
- **`stats_len`**: Length of the array (typically `6`).

### `ebpfdivert_set_print`
```c
void ebpfdivert_set_print(ebpfdivert_print_fn_t print_fn);
```
Registers a custom print callback function to receive logging output from the library and `libbpf`.
- **`print_fn`**: Pointer to the custom callback function.
