# nf-flowmeter

A Zeek script that extracts the **53 NF-v3 NetFlow v9 features** directly from network traffic (PCAP files or live capture). The output is fully compatible with machine-learning models trained on the [NF-CSE-CIC-IDS2018-v3](https://staff.itee.uq.edu.au/marius/NIDS_datasets/) dataset series from the University of Queensland.

Each completed flow is written as a single JSON line to `flowmeter.log`, with all 53 feature fields named exactly as they appear in the NF-v3 dataset.

---

## Table of Contents

- [Why This Exists](#why-this-exists)
- [Features at a Glance](#features-at-a-glance)
- [Complete Feature Reference (53 Fields)](#complete-feature-reference-53-fields)
- [Installation](#installation)
- [Usage](#usage)
- [Output Format](#output-format)
- [Merging with Labels (CSV Export)](#merging-with-labels-csv-export)
- [Technical Details](#technical-details)
- [Performance Notes](#performance-notes)
- [License](#license)

---

## Why This Exists

Researchers and security engineers who train IDS/IPS models on the **NF-v3 dataset series** need a way to extract the same 53 features from their own traffic. The standard tool for this is **nProbe**, which is commercial and closed-source.

**nf-flowmeter** solves this by reimplementing the full NF-v3 feature set as a pure Zeek script — no external C libraries, no nDPI dependency, no license fees. Just run Zeek against any PCAP and get a ready-to-use feature file.

---

## Features at a Glance

| Category | What is extracted |
|---|---|
| **Flow Identity** | Source/destination IPv4, source/destination port, IANA protocol number |
| **Volume** | Byte counts and packet counts per direction (IP-level) |
| **Timing** | Flow duration (ms), start/end timestamps (ms since epoch) |
| **IP Header** | Min/max IP packet length, min/max TTL |
| **Throughput** | Bytes/sec and average throughput per direction |
| **TCP** | Retransmission bytes/packets, max window size per direction, cumulative flag bitmasks (client, server, combined) |
| **Packet Histogram** | 5-bin packet size distribution (≤128, 129–256, 257–512, 513–1024, 1025–1514+ bytes) |
| **Inter-Arrival Time** | Min, max, mean, and standard deviation per direction (microseconds) |
| **ICMP** | ICMP type, ICMP IPv4 type (embedded protocol from unreachable/time-exceeded) |
| **DNS** | Query ID, query type, answer TTL, response code |
| **FTP** | Last FTP reply code |
| **HTTP** | Request method, URL, User-Agent |
| **L7 Protocol** | Zeek-detected application protocol (uppercased service string, e.g. `HTTP`, `DNS`, `SSL`) |

---

## Complete Feature Reference (53 Fields)

Every row in `flowmeter.log` contains exactly these 53 fields in canonical order:

| # | Field Name | Type | Description |
|---|---|---|---|
| 1 | `IPV4_SRC_ADDR` | addr | Source IP address |
| 2 | `L4_SRC_PORT` | count | Source port |
| 3 | `IPV4_DST_ADDR` | addr | Destination IP address |
| 4 | `L4_DST_PORT` | count | Destination port |
| 5 | `PROTOCOL` | count | IANA protocol number (6=TCP, 17=UDP, 1=ICMP, 58=ICMPv6) |
| 6 | `IN_BYTES` | count | IP-level bytes, source → destination |
| 7 | `OUT_BYTES` | count | IP-level bytes, destination → source |
| 8 | `IN_PKTS` | count | Packets, source → destination |
| 9 | `OUT_PKTS` | count | Packets, destination → source |
| 10 | `FLOW_DURATION_MILLISECONDS` | double | Flow duration in milliseconds |
| 11 | `MIN_IP_PKT_LEN` | count | Smallest full IP packet observed |
| 12 | `MAX_IP_PKT_LEN` | count | Largest full IP packet observed |
| 13 | `SRC_TO_DST_SECOND_BYTES` | double | Src→Dst IP bytes per second |
| 14 | `DST_TO_SRC_SECOND_BYTES` | double | Dst→Src IP bytes per second |
| 15 | `SRC_TO_DST_AVG_THROUGHPUT` | double | Src→Dst average throughput |
| 16 | `DST_TO_SRC_AVG_THROUGHPUT` | double | Dst→Src average throughput |
| 17 | `RETRANSMITTED_IN_BYTES` | count | Retransmitted bytes, src→dst |
| 18 | `RETRANSMITTED_IN_PKTS` | count | Retransmitted packets, src→dst |
| 19 | `RETRANSMITTED_OUT_BYTES` | count | Retransmitted bytes, dst→src |
| 20 | `RETRANSMITTED_OUT_PKTS` | count | Retransmitted packets, dst→src |
| 21 | `NUM_PKTS_UP_TO_128_BYTES` | count | Packets ≤ 128 bytes |
| 22 | `NUM_PKTS_128_TO_256_BYTES` | count | Packets 129–256 bytes |
| 23 | `NUM_PKTS_256_TO_512_BYTES` | count | Packets 257–512 bytes |
| 24 | `NUM_PKTS_512_TO_1024_BYTES` | count | Packets 513–1024 bytes |
| 25 | `NUM_PKTS_1024_TO_1514_BYTES` | count | Packets 1025+ bytes |
| 26 | `TCP_WIN_MAX_IN` | count | Max TCP window, src→dst |
| 27 | `TCP_WIN_MAX_OUT` | count | Max TCP window, dst→src |
| 28 | `CLIENT_TCP_FLAGS` | count | Cumulative TCP flag bitmask, client |
| 29 | `SERVER_TCP_FLAGS` | count | Cumulative TCP flag bitmask, server |
| 30 | `TCP_FLAGS` | count | Combined TCP flag bitmask (client \| server) |
| 31 | `MIN_TTL` | count | Minimum TTL (or hop limit for IPv6) |
| 32 | `MAX_TTL` | count | Maximum TTL (or hop limit for IPv6) |
| 33 | `ICMP_TYPE` | count | ICMP message type |
| 34 | `ICMP_IPV4_TYPE` | count | Protocol number from ICMP error payload |
| 35 | `DNS_QUERY_ID` | count | DNS transaction ID |
| 36 | `DNS_QUERY_TYPE` | count | DNS query type (1=A, 28=AAAA, etc.) |
| 37 | `DNS_TTL_ANSWER` | count | TTL from the DNS answer section |
| 38 | `DNS_RESPONSE_CODE` | count | DNS response code (0=NOERROR, 3=NXDOMAIN, etc.) |
| 39 | `FTP_COMMAND_RET_CODE` | count | Last FTP reply code (e.g. 220, 331, 530) |
| 40 | `L7_PROTO` | string | Application-layer protocol (`HTTP`, `DNS`, `SSL`, `FTP`, etc.) |
| 41 | `HTTP_URL` | string | HTTP request URI |
| 42 | `HTTP_METHOD` | string | HTTP request method (GET, POST, etc.) |
| 43 | `HTTP_USER_AGENT` | string | HTTP User-Agent header |
| 44 | `FLOW_START_MILLISECONDS` | double | Flow start time (ms since Unix epoch) |
| 45 | `FLOW_END_MILLISECONDS` | double | Flow end time (ms since Unix epoch) |
| 46 | `SRC_TO_DST_IAT_MIN` | double | Min inter-arrival time, src→dst (μs) |
| 47 | `SRC_TO_DST_IAT_MAX` | double | Max inter-arrival time, src→dst (μs) |
| 48 | `SRC_TO_DST_IAT_AVG` | double | Mean inter-arrival time, src→dst (μs) |
| 49 | `SRC_TO_DST_IAT_STDDEV` | double | Std dev inter-arrival time, src→dst (μs) |
| 50 | `DST_TO_SRC_IAT_MIN` | double | Min inter-arrival time, dst→src (μs) |
| 51 | `DST_TO_SRC_IAT_MAX` | double | Max inter-arrival time, dst→src (μs) |
| 52 | `DST_TO_SRC_IAT_AVG` | double | Mean inter-arrival time, dst→src (μs) |
| 53 | `DST_TO_SRC_IAT_STDDEV` | double | Std dev inter-arrival time, dst→src (μs) |

---

## Installation

### Prerequisites

- **Zeek 5.0+** (tested on Zeek 8.0)
- **zkg** (Zeek package manager) — bundled with the standard Zeek install

### Option A — Install via zkg (recommended)

```bash
git clone https://github.com/Matesfu/nf-flowmeter.git
cd nf-flowmeter
zkg install .
```
Once installed, the package is auto-loaded when Zeek uses `@load packages`.

### Option B — Manual install

```bash
ZEEK_SCRIPTS=$(zeek-config --script_dir)
sudo mkdir -p ${ZEEK_SCRIPTS}/site/nf-flowmeter
sudo cp -r scripts/* ${ZEEK_SCRIPTS}/site/nf-flowmeter/
```

Then add to your `/opt/zeek/share/zeek/site/local.zeek`:

```zeek
@load nf-flowmeter
```

---

## Usage

### Offline PCAP Analysis

```bash
mkdir -p ~/zeek-output && cd ~/zeek-output
zeek -C -r /path/to/traffic.pcap nf-flowmeter
```

This produces `flowmeter.log` (and Zeek's standard `conn.log`, `dns.log`, etc.).

### Live Capture (native Linux only)

```bash
zeekctl deploy
```

> **Note:** Live capture requires a native Linux installation. It does not work on WSL because WSL lacks access to raw network interfaces.

---

## Output Format

`flowmeter.log` is written in **JSON format** — one flow per line:

```json
{
  "IPV4_SRC_ADDR": "10.0.0.1",
  "L4_SRC_PORT": 54321,
  "IPV4_DST_ADDR": "192.168.1.1",
  "L4_DST_PORT": 443,
  "PROTOCOL": 6,
  "IN_BYTES": 1520,
  "OUT_BYTES": 8340,
  "IN_PKTS": 12,
  "OUT_PKTS": 18,
  "FLOW_DURATION_MILLISECONDS": 342.5,
  "MIN_IP_PKT_LEN": 40,
  "MAX_IP_PKT_LEN": 1500,
  "...": "..."
}
```

### Zero-Packet Flow Guard

Flows where no actual packet was observed (e.g., synthetic connection records from protocol analyzers) are **not** emitted. This prevents rows with meaningless sentinel values from polluting the dataset.

### Sentinel Handling

Fields like `MIN_TTL` and `MIN_IP_PKT_LEN` are initialized to high sentinel values during tracking. If no qualifying packet is observed for a flow, these fields are **reset to 0** in the output rather than leaking sentinel values.

---

## Merging with Labels (CSV Export)

A helper script `merge_nf_features.py` is included to merge `flowmeter.log` with `conn.log` into a single CSV with NF-v3 column ordering:

```bash
python3 merge_nf_features.py \
    --flowmeter flowmeter.log \
    --conn conn.log \
    --output nf_features.csv
```

You can also attach labels for supervised learning:

```bash
python3 merge_nf_features.py \
    --flowmeter flowmeter.log \
    --conn conn.log \
    --output nf_features.csv \
    --label "Benign"
```

The output CSV uses the exact NF-v3 column names, ready for direct use with models trained on NF-CSE-CIC-IDS2018-v3.

---

## Technical Details

### How It Works

1. **`new_connection`** — Initializes per-flow state tables when Zeek sees a new connection.
2. **`new_packet`** — Processes every packet to update counters: packet counts, IP packet length extremes, TTL extremes, packet-size histogram bins, TCP flags/window, and inter-arrival times.
3. **`tcp_rexmit`** — Tracks TCP retransmission bytes and packets per direction.
4. **Protocol-specific events** — `icmp_sent`, `dns_request`, `dns_*_reply`, `ftp_reply`, `http_request`, `http_header` — populate application-layer feature caches (ICMP, DNS, FTP, HTTP).
5. **`connection_state_remove`** — When a flow ends, all 53 features are finalized and written as a single JSON record to `flowmeter.log`. Per-flow state is then cleaned up to free memory.

### Memory Efficiency

- IAT statistics use **O(1) running accumulators** (Welford's method) instead of storing every packet timestamp, keeping memory usage constant regardless of flow length.
- All per-flow state is stored in global tables keyed by connection UID and explicitly cleaned up at flow teardown.

### Protocol Number Handling

- TCP = 6, UDP = 17, ICMP = 1, ICMPv6 = 58
- ICMPv4 vs ICMPv6 is distinguished by checking the source address family, since Zeek's `transport_proto` enum has no separate `icmp6` value.

### TCP Flag Bitmask Format

Flags follow the standard NetFlow v9 / nProbe bitmask format:

| Bit | Value | Flag |
|-----|-------|------|
| 0 | `0x01` | FIN |
| 1 | `0x02` | SYN |
| 2 | `0x04` | RST |
| 3 | `0x08` | PSH |
| 4 | `0x10` | ACK |
| 5 | `0x20` | URG |
| 6 | `0x40` | ECE |
| 7 | `0x80` | CWR |

Example: a value of `18` (0x12) means SYN + ACK.

### L7 Protocol Detection

`L7_PROTO` contains the **Zeek service string in uppercase** (e.g., `HTTP`, `DNS`, `SSL`, `FTP`). If Zeek detects multiple services on a connection (comma-separated), only the first is used. An empty string means no application protocol was identified.

> **Note:** This is not the nDPI numeric protocol ID. If your model requires nDPI IDs, you can map these strings to integers in your preprocessing pipeline.

---

## Performance Notes

This script performs **per-packet processing** (`new_packet` event), which is inherently more resource-intensive than connection-level analysis. It is designed primarily for **offline PCAP analysis**, which is the standard workflow for IDS dataset feature extraction.

For live traffic exceeding ~1 Gbps, consider using a Zeek cluster configuration to distribute the workload.

---

## License

MIT

---

## Credits

- **NF-v3 dataset series** — University of Queensland ITEE: https://staff.itee.uq.edu.au/marius/NIDS_datasets/
