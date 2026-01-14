# Darkflow eBPF Packet Processing Workflow

This document explains how DarkFlow captures, processes, and exports IPv4/IPv6 traffic features using Aya eBPF.

## Packet Flow Overview

```text
[Network Packet]
        ↓
[Network Interface (NIC) / Kernel Network Stack]
        ↓
[TC (Traffic Control) Hook: tc_flow_track]
        ↓
+---------------------------------+
| Kernel-space eBPF               |
|  - Parse Ethernet/IP            |
|  - Parse Transport              |
|  - Build PacketInfo             |
|  - Convert → `EbpfEvent* `      |
|  - Submit to eBPF Maps/RingBuf  |
+---------------------------------+
        ↓
[User-space program `darkflow run`]
        ↓
+----------------------------------+
|- Read `EbpfEvent*` from RingBuf  |
|- Feature extraction              |
|- Flow timeout check              |
|- Feature Extraction → CSV → ML/DL|
+----------------------------------+
```

**Explanation**:

* **TC (Traffic Control)**: Linux kernel hook for monitoring and controlling network traffic on an interface.
* **eBPF Program**: Executes inside the kernel, collects features, and populates maps.
* **RingBuf**: Efficient shared buffer from kernel to user space.
* **Per-CPU Array**: Each CPU keeps separate counters (e.g., dropped packets) to avoid contention.

## Kernel-space Processing

### a. TC Classifier

```rust
#[classifier]
pub fn tc_flow_track(ctx: TcContext) -> i32 { ... }
```

* Triggered for each packet passing the interface.
* Returns **TC_ACT_PIPE** to allow the packet to continue.
* Calls `process_packet` to parse and handle traffic.

---

### b. Parsing Packets

1. **Ethernet header (EthHdr)**:

   * Determines `ether_type` (IPv4, IPv6, ARP…)
   * Length: 14 bytes (`EthHdr::LEN`)

2. **IPv4 header (Ipv4Hdr)**:

   * `ihl` field → header length in 32-bit words
   * `proto` field → identifies TCP, UDP, or ICMP

3. **Transport Layer (TCP/UDP/ICMP)**:

   * Offset calculated: `EthHdr::LEN + ip_header_length`
   * Handled generically using the **NetworkHeader trait**

---

### c. Event Creation

* **PacketInfo**: Temporary kernel-space struct storing:

  * Source/destination IP
  * Data length
  * Protocol

* **EbpfEventIpv4 / EbpfEventIpv6**:

  * Standardized event structure (32 bytes IPv4, 64 bytes IPv6)
  * Includes ports, TCP flags, sequence numbers, ICMP type/code
  * Submitted to **RingBuf** for user-space consumption

* **Dropped Packets**: If RingBuf is full, increment `DROPPED_PACKETS` (Per-CPU counter)

---

### d. NetworkHeader Trait

```rust
pub trait NetworkHeader { ... }
```

* Provides a **unified interface** for TCP, UDP, ICMP headers.
* Allows `process_transport_packet` to handle all protocols generically.
* Example methods:

  * `source_port()`, `destination_port()`
  * `window_size()`, `combined_flags()`
  * `sequence_number()`, `icmp_type()`, `icmp_code()`

## eBPF Maps and Buffers

| Map / Buffer      | Type             | Purpose                                        |
| ----------------- | ---------------- | ---------------------------------------------- |
| `EVENTS_IPV4`     | RingBuf          | Transport events to user-space (20 MB)         |
| `DROPPED_PACKETS` | PerCpuArray<u64> | Counts packets dropped because RingBuf is full |

* **RingBuf**: Supports high-speed kernel → user-space communication.
* **Per-CPU map**: Avoids lock contention across multiple CPU cores.

## User-space Processing

* **Reads events** from RingBuf periodically.
* **Checks flow expiration**:

  * `idle_timeout`: Max idle time per flow
  * `active_timeout`: Max lifetime per flow
  * `expiration_check_interval`: Interval to sweep flows
* **Exports features**:

  * Duration, byte count, packet count
  * TCP flags, window size, header lengths
  * ICMP type/code
* **Outputs**:

  * CSV files
  * Console prints
  * Feeds ML models or IDS systems
