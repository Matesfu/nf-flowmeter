# nf-flowmeter — Extended Zeek Feature Extractor for NF-CSE-CIC-IDS2018-v3

Extended version of [zeek-flowmeter](https://github.com/zeek-flowmeter/zeek-flowmeter)
with full NetFlow v9 feature parity for IDS/IPS model inference against models
trained on **NF-CSE-CIC-IDS2018-v3** (and the broader NF-v3 dataset series from
the University of Queensland).

---

## What This Adds Over Original zeek-flowmeter

The original zeek-flowmeter covers statistical flow features (IAT, packet size
stats, subflow, bulk, active/idle). This extension adds every NF-v3 NetFlow v9
feature that is extractable from Zeek without embedding the nDPI C library:

| Feature Group | Features Added |
|---|---|
| IP header | `MIN_TTL`, `MAX_TTL`, `MIN_IP_PKT_LEN`, `MAX_IP_PKT_LEN` (full IP packet) |
| IP-level byte counts | `IN_BYTES`, `OUT_BYTES` (IP-level, matching nProbe semantics) |
| Per-direction throughput | `SRC_TO_DST_SECOND_BYTES`, `DST_TO_SRC_SECOND_BYTES`, `SRC_TO_DST_AVG_THROUGHPUT`, `DST_TO_SRC_AVG_THROUGHPUT` |
| TCP retransmission | `RETRANSMITTED_IN_BYTES`, `RETRANSMITTED_IN_PKTS`, `RETRANSMITTED_OUT_BYTES`, `RETRANSMITTED_OUT_PKTS` |
| Packet size histogram | `NUM_PKTS_UP_TO_128_BYTES`, `NUM_PKTS_128_TO_256_BYTES`, `NUM_PKTS_256_TO_512_BYTES`, `NUM_PKTS_512_TO_1024_BYTES`, `NUM_PKTS_1024_TO_1514_BYTES` |
| TCP window (max over flow) | `TCP_WIN_MAX_IN`, `TCP_WIN_MAX_OUT` |
| TCP flags (combined bitmask) | `CLIENT_TCP_FLAGS`, `SERVER_TCP_FLAGS`, `TCP_FLAGS` |
| ICMP | `ICMP_TYPE`, `ICMP_IPV4_TYPE` |
| DNS (application layer) | `DNS_QUERY_ID`, `DNS_QUERY_TYPE`, `DNS_TTL_ANSWER`, `DNS_RESPONSE_CODE` |
| FTP (application layer) | `FTP_COMMAND_RET_CODE` |
| HTTP (application layer) | `HTTP_URL`, `HTTP_METHOD`, `HTTP_USER_AGENT` |
| NF-v3 IAT naming | `SRC_TO_DST_IAT_MIN/MAX/AVG/STDDEV`, `DST_TO_SRC_IAT_MIN/MAX/AVG/STDDEV` |
| NF-v3 timestamps | `FLOW_START_MILLISECONDS`, `FLOW_END_MILLISECONDS` |
| L7 protocol string | `L7_PROTO_STR` (Zeek service string — see note below) |

### What Is NOT Implemented

**`L7_PROTO` (nDPI numeric ID):** nProbe uses the nDPI deep packet inspection
library which assigns numeric protocol IDs (e.g., 7=HTTP, 91=SSH/TLS). Zeek
uses its own Dynamic Protocol Detection engine with different numeric IDs.
Producing exact nDPI-compatible numeric IDs from Zeek requires embedding the
nDPI C library as a compiled Zeek plugin — not achievable in a pure Zeek script.

`L7_PROTO_STR` is written instead (e.g., "http", "ssl", "dns", "ssh"). You can
map these strings to nDPI-compatible integers using a lookup table in your ML
preprocessing pipeline if needed.

---

## Complete Feature List in flowmeter.log

### Flow Identity (from conn.log via uid)
```
uid
```

### Original zeek-flowmeter Features (preserved)
```
flow_duration
fwd_pkts_tot              bwd_pkts_tot
fwd_data_pkts_tot         bwd_data_pkts_tot
fwd_pkts_per_sec          bwd_pkts_per_sec          flow_pkts_per_sec
down_up_ratio
fwd_header_size_tot       fwd_header_size_min        fwd_header_size_max
bwd_header_size_tot       bwd_header_size_min        bwd_header_size_max
fwd_pkts_payload_max      fwd_pkts_payload_min       fwd_pkts_payload_tot
fwd_pkts_payload_avg      fwd_pkts_payload_std
bwd_pkts_payload_max      bwd_pkts_payload_min       bwd_pkts_payload_tot
bwd_pkts_payload_avg      bwd_pkts_payload_std
flow_pkts_payload_max     flow_pkts_payload_min      flow_pkts_payload_tot
flow_pkts_payload_avg     flow_pkts_payload_std
payload_bytes_per_sec
flow_FIN_flag_count       flow_SYN_flag_count        flow_RST_flag_count
fwd_PSH_flag_count        bwd_PSH_flag_count         flow_ACK_flag_count
fwd_URG_flag_count        bwd_URG_flag_count
flow_CWR_flag_count       flow_ECE_flag_count
fwd_iat_max               fwd_iat_min                fwd_iat_tot
fwd_iat_avg               fwd_iat_std
bwd_iat_max               bwd_iat_min                bwd_iat_tot
bwd_iat_avg               bwd_iat_std
flow_iat_max              flow_iat_min               flow_iat_tot
flow_iat_avg              flow_iat_std
fwd_subflow_pkts          bwd_subflow_pkts
fwd_subflow_bytes         bwd_subflow_bytes
fwd_bulk_bytes            bwd_bulk_bytes
fwd_bulk_packets          bwd_bulk_packets
fwd_bulk_rate             bwd_bulk_rate
active_max                active_min                 active_tot
active_avg                active_std
idle_max                  idle_min                   idle_tot
idle_avg                  idle_std
fwd_init_window_size      bwd_init_window_size
fwd_last_window_size      bwd_last_window_size
```

### NEW — NF-v3 NetFlow v9 Features
```
IN_BYTES                  OUT_BYTES
IN_PKTS                   OUT_PKTS
MIN_IP_PKT_LEN            MAX_IP_PKT_LEN
SRC_TO_DST_SECOND_BYTES   DST_TO_SRC_SECOND_BYTES
SRC_TO_DST_AVG_THROUGHPUT DST_TO_SRC_AVG_THROUGHPUT
RETRANSMITTED_IN_BYTES    RETRANSMITTED_IN_PKTS
RETRANSMITTED_OUT_BYTES   RETRANSMITTED_OUT_PKTS
NUM_PKTS_UP_TO_128_BYTES  NUM_PKTS_128_TO_256_BYTES
NUM_PKTS_256_TO_512_BYTES NUM_PKTS_512_TO_1024_BYTES
NUM_PKTS_1024_TO_1514_BYTES
TCP_WIN_MAX_IN            TCP_WIN_MAX_OUT
CLIENT_TCP_FLAGS          SERVER_TCP_FLAGS           TCP_FLAGS
MIN_TTL                   MAX_TTL
ICMP_TYPE                 ICMP_IPV4_TYPE
DNS_QUERY_ID              DNS_QUERY_TYPE
DNS_TTL_ANSWER            DNS_RESPONSE_CODE
FTP_COMMAND_RET_CODE
HTTP_URL                  HTTP_METHOD                HTTP_USER_AGENT
L7_PROTO_STR
FLOW_START_MILLISECONDS   FLOW_END_MILLISECONDS
SRC_TO_DST_IAT_MIN        SRC_TO_DST_IAT_MAX
SRC_TO_DST_IAT_AVG        SRC_TO_DST_IAT_STDDEV
DST_TO_SRC_IAT_MIN        DST_TO_SRC_IAT_MAX
DST_TO_SRC_IAT_AVG        DST_TO_SRC_IAT_STDDEV
```

---

## Installation

### Prerequisites

- Zeek 5.0 or later (tested on Zeek 8.0)
- zkg (Zeek package manager) — included with Zeek binary packages

### Method 1 — Install via zkg (recommended)

```bash
# Clone the repository
git clone https://github.com/YOUR_USERNAME/nf-flowmeter.git

# Install using zkg from the cloned directory
cd nf-flowmeter
zkg install .
```

### Method 2 — Manual installation

```bash
# Find your Zeek script directory
ZEEKSCRIPTDIR=$(zeek-config --script_dir)

# Create the package directory and copy scripts
sudo mkdir -p ${ZEEKSCRIPTDIR}/site/nf-flowmeter
sudo cp -r scripts/* ${ZEEKSCRIPTDIR}/site/nf-flowmeter/
```

### Load in local.zeek

Add to `/opt/zeek/share/zeek/site/local.zeek`:

```zeek
@load packages          # if installed via zkg
# OR
@load nf-flowmeter      # if installed manually

redef ignore_checksums = T;
redef LogAscii::use_json = T;
```

---

## Usage

### PCAP mode (works on WSL and any Linux)

```bash
# Create output directory
mkdir -p ~/zeek-output && cd ~/zeek-output

# Run against a PCAP file
zeek -C -r /path/to/traffic.pcap nf-flowmeter

# OR using local.zeek (which loads the package)
zeek -C -r /path/to/traffic.pcap local
```

### Live capture mode (native Linux only — not WSL)

```bash
zeekctl deploy
```

### Output logs

After running, you will find:

```
flowmeter.log   — all flow features (original + NF-v3 fields)
conn.log        — Zeek standard connection log (join key: uid)
dns.log         — DNS transactions
http.log        — HTTP transactions
ftp.log         — FTP transactions
ssl.log         — TLS/SSL info
```

---

## Merging flowmeter.log with conn.log

Every `flowmeter.log` record contains a `uid` field that matches the `uid` in
`conn.log`. The flow identity fields (src/dst IP and port, protocol) are in
`conn.log`. To produce a complete NF-v3-style feature row, join on `uid`:

```python
import json, csv

def read_zeek_log(path):
    records = {}
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            try:
                r = json.loads(line)
                if 'uid' in r:
                    records[r['uid']] = r
            except:
                continue
    return records

conn = read_zeek_log('conn.log')
flow = read_zeek_log('flowmeter.log')

merged = []
for uid, f in flow.items():
    c = conn.get(uid, {})
    row = {**f, **c}  # conn fields take precedence for identity fields
    merged.append(row)

# Write to CSV
if merged:
    with open('nf_features.csv', 'w', newline='') as out:
        writer = csv.DictWriter(out, fieldnames=list(merged[0].keys()))
        writer.writeheader()
        writer.writerows(merged)

print(f"Wrote {len(merged)} flow records to nf_features.csv")
```

---

## NF-v3 Feature Name Mapping

Use this table to rename columns to match NF-CSE-CIC-IDS2018-v3 training column
names in your ML preprocessing pipeline:

| NF-v3 Column Name | Source in this extractor |
|---|---|
| `IPV4_SRC_ADDR` | `conn.log` → `id.orig_h` |
| `L4_SRC_PORT` | `conn.log` → `id.orig_p` |
| `IPV4_DST_ADDR` | `conn.log` → `id.resp_h` |
| `L4_DST_PORT` | `conn.log` → `id.resp_p` |
| `PROTOCOL` | `conn.log` → `proto` |
| `IN_BYTES` | `flowmeter.log` → `IN_BYTES` |
| `OUT_BYTES` | `flowmeter.log` → `OUT_BYTES` |
| `IN_PKTS` | `flowmeter.log` → `IN_PKTS` |
| `OUT_PKTS` | `flowmeter.log` → `OUT_PKTS` |
| `FLOW_DURATION_MILLISECONDS` | `flowmeter.log` → `flow_duration × 1000` |
| `MIN_IP_PKT_LEN` | `flowmeter.log` → `MIN_IP_PKT_LEN` |
| `MAX_IP_PKT_LEN` | `flowmeter.log` → `MAX_IP_PKT_LEN` |
| `SRC_TO_DST_SECOND_BYTES` | `flowmeter.log` → `SRC_TO_DST_SECOND_BYTES` |
| `DST_TO_SRC_SECOND_BYTES` | `flowmeter.log` → `DST_TO_SRC_SECOND_BYTES` |
| `SRC_TO_DST_AVG_THROUGHPUT` | `flowmeter.log` → `SRC_TO_DST_AVG_THROUGHPUT` |
| `DST_TO_SRC_AVG_THROUGHPUT` | `flowmeter.log` → `DST_TO_SRC_AVG_THROUGHPUT` |
| `RETRANSMITTED_IN_BYTES` | `flowmeter.log` → `RETRANSMITTED_IN_BYTES` |
| `RETRANSMITTED_IN_PKTS` | `flowmeter.log` → `RETRANSMITTED_IN_PKTS` |
| `RETRANSMITTED_OUT_BYTES` | `flowmeter.log` → `RETRANSMITTED_OUT_BYTES` |
| `RETRANSMITTED_OUT_PKTS` | `flowmeter.log` → `RETRANSMITTED_OUT_PKTS` |
| `NUM_PKTS_UP_TO_128_BYTES` | `flowmeter.log` → `NUM_PKTS_UP_TO_128_BYTES` |
| `NUM_PKTS_128_TO_256_BYTES` | `flowmeter.log` → `NUM_PKTS_128_TO_256_BYTES` |
| `NUM_PKTS_256_TO_512_BYTES` | `flowmeter.log` → `NUM_PKTS_256_TO_512_BYTES` |
| `NUM_PKTS_512_TO_1024_BYTES` | `flowmeter.log` → `NUM_PKTS_512_TO_1024_BYTES` |
| `NUM_PKTS_1024_TO_1514_BYTES` | `flowmeter.log` → `NUM_PKTS_1024_TO_1514_BYTES` |
| `TCP_WIN_MAX_IN` | `flowmeter.log` → `TCP_WIN_MAX_IN` |
| `TCP_WIN_MAX_OUT` | `flowmeter.log` → `TCP_WIN_MAX_OUT` |
| `TCP_FLAGS` | `flowmeter.log` → `TCP_FLAGS` |
| `CLIENT_TCP_FLAGS` | `flowmeter.log` → `CLIENT_TCP_FLAGS` |
| `SERVER_TCP_FLAGS` | `flowmeter.log` → `SERVER_TCP_FLAGS` |
| `MIN_TTL` | `flowmeter.log` → `MIN_TTL` |
| `MAX_TTL` | `flowmeter.log` → `MAX_TTL` |
| `ICMP_TYPE` | `flowmeter.log` → `ICMP_TYPE` |
| `ICMP_IPV4_TYPE` | `flowmeter.log` → `ICMP_IPV4_TYPE` |
| `DNS_QUERY_ID` | `flowmeter.log` → `DNS_QUERY_ID` |
| `DNS_QUERY_TYPE` | `flowmeter.log` → `DNS_QUERY_TYPE` |
| `DNS_TTL_ANSWER` | `flowmeter.log` → `DNS_TTL_ANSWER` |
| `DNS_RESPONSE_CODE` | `flowmeter.log` → `DNS_RESPONSE_CODE` |
| `FTP_COMMAND_RET_CODE` | `flowmeter.log` → `FTP_COMMAND_RET_CODE` |
| `L7_PROTO` | ⚠️ NOT AVAILABLE — use `L7_PROTO_STR` + manual mapping |
| `HTTP_URL` | `flowmeter.log` → `HTTP_URL` |
| `HTTP_METHOD` | `flowmeter.log` → `HTTP_METHOD` |
| `HTTP_USER_AGENT` | `flowmeter.log` → `HTTP_USER_AGENT` |
| `FLOW_START_MILLISECONDS` | `flowmeter.log` → `FLOW_START_MILLISECONDS` |
| `FLOW_END_MILLISECONDS` | `flowmeter.log` → `FLOW_END_MILLISECONDS` |
| `SRC_TO_DST_IAT_MIN` | `flowmeter.log` → `SRC_TO_DST_IAT_MIN` |
| `SRC_TO_DST_IAT_MAX` | `flowmeter.log` → `SRC_TO_DST_IAT_MAX` |
| `SRC_TO_DST_IAT_AVG` | `flowmeter.log` → `SRC_TO_DST_IAT_AVG` |
| `SRC_TO_DST_IAT_STDDEV` | `flowmeter.log` → `SRC_TO_DST_IAT_STDDEV` |
| `DST_TO_SRC_IAT_MIN` | `flowmeter.log` → `DST_TO_SRC_IAT_MIN` |
| `DST_TO_SRC_IAT_MAX` | `flowmeter.log` → `DST_TO_SRC_IAT_MAX` |
| `DST_TO_SRC_IAT_AVG` | `flowmeter.log` → `DST_TO_SRC_IAT_AVG` |
| `DST_TO_SRC_IAT_STDDEV` | `flowmeter.log` → `DST_TO_SRC_IAT_STDDEV` |

---

## TCP Flag Bitmask Reference

`CLIENT_TCP_FLAGS`, `SERVER_TCP_FLAGS`, and `TCP_FLAGS` are stored as integer
bitmasks in NetFlow v9 format — the same format nProbe uses:

| Bit | Value | Flag |
|---|---|---|
| 0 | 0x01 | FIN |
| 1 | 0x02 | SYN |
| 2 | 0x04 | RST |
| 3 | 0x08 | PSH |
| 4 | 0x10 | ACK |
| 5 | 0x20 | URG |
| 6 | 0x40 | ECE |
| 7 | 0x80 | CWR |

Example: A value of `0x12` (18) means SYN + ACK flags were seen.

---

## DNS Query Type Reference

`DNS_QUERY_TYPE` is stored as the numeric IANA DNS resource record type:

| Value | Type | Description |
|---|---|---|
| 1 | A | IPv4 address |
| 2 | NS | Nameserver |
| 5 | CNAME | Canonical name |
| 15 | MX | Mail exchange |
| 28 | AAAA | IPv6 address |
| 255 | ANY | Any record type |

---

## Performance Notes

This script performs per-packet computation which is resource intensive.
It is designed for **offline PCAP analysis** (the standard method for IDS
dataset feature extraction). For live traffic at high throughput (>1 Gbps),
consider using a Zeek cluster configuration.

---

## License

MIT — same as the original zeek-flowmeter project.

## Credits

- Original zeek-flowmeter: https://github.com/zeek-flowmeter/zeek-flowmeter
- NF-v3 dataset series: University of Queensland ITEE —
  https://staff.itee.uq.edu.au/marius/NIDS_datasets/
