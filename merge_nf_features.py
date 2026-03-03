#!/usr/bin/env python3
"""
merge_nf_features.py
====================
Merges Zeek flowmeter.log + conn.log into a single CSV with NF-v3 column names
compatible with models trained on NF-CSE-CIC-IDS2018-v3.

Usage:
    python3 merge_nf_features.py \
        --flowmeter flowmeter.log \
        --conn      conn.log \
        --output    nf_features.csv \
        [--label    Benign]

The --label argument adds a Label column to every row (optional).
Use it when building labelled training/test datasets from known PCAPs.
"""

import argparse
import csv
import json
import sys
from pathlib import Path


# ── NF-v3 column rename map ────────────────────────────────────────────────
# Maps (source, zeek_field) → nf_v3_column_name
# source: "conn" = from conn.log, "flow" = from flowmeter.log
NF_V3_RENAME = {
    # Flow identity — from conn.log
    ("conn", "id.orig_h"):          "IPV4_SRC_ADDR",
    ("conn", "id.orig_p"):          "L4_SRC_PORT",
    ("conn", "id.resp_h"):          "IPV4_DST_ADDR",
    ("conn", "id.resp_p"):          "L4_DST_PORT",
    ("conn", "proto"):              "PROTOCOL",

    # Core byte/packet counts — from flowmeter.log
    ("flow", "IN_BYTES"):           "IN_BYTES",
    ("flow", "OUT_BYTES"):          "OUT_BYTES",
    ("flow", "IN_PKTS"):            "IN_PKTS",
    ("flow", "OUT_PKTS"):           "OUT_PKTS",

    # Duration (convert seconds → milliseconds)
    # Handled programmatically below — see COMPUTED_FIELDS

    # Packet length
    ("flow", "MIN_IP_PKT_LEN"):     "MIN_IP_PKT_LEN",
    ("flow", "MAX_IP_PKT_LEN"):     "MAX_IP_PKT_LEN",

    # Throughput
    ("flow", "SRC_TO_DST_SECOND_BYTES"):    "SRC_TO_DST_SECOND_BYTES",
    ("flow", "DST_TO_SRC_SECOND_BYTES"):    "DST_TO_SRC_SECOND_BYTES",
    ("flow", "SRC_TO_DST_AVG_THROUGHPUT"):  "SRC_TO_DST_AVG_THROUGHPUT",
    ("flow", "DST_TO_SRC_AVG_THROUGHPUT"):  "DST_TO_SRC_AVG_THROUGHPUT",

    # Retransmission
    ("flow", "RETRANSMITTED_IN_BYTES"):     "RETRANSMITTED_IN_BYTES",
    ("flow", "RETRANSMITTED_IN_PKTS"):      "RETRANSMITTED_IN_PKTS",
    ("flow", "RETRANSMITTED_OUT_BYTES"):    "RETRANSMITTED_OUT_BYTES",
    ("flow", "RETRANSMITTED_OUT_PKTS"):     "RETRANSMITTED_OUT_PKTS",

    # Packet histogram
    ("flow", "NUM_PKTS_UP_TO_128_BYTES"):       "NUM_PKTS_UP_TO_128_BYTES",
    ("flow", "NUM_PKTS_128_TO_256_BYTES"):      "NUM_PKTS_128_TO_256_BYTES",
    ("flow", "NUM_PKTS_256_TO_512_BYTES"):      "NUM_PKTS_256_TO_512_BYTES",
    ("flow", "NUM_PKTS_512_TO_1024_BYTES"):     "NUM_PKTS_512_TO_1024_BYTES",
    ("flow", "NUM_PKTS_1024_TO_1514_BYTES"):    "NUM_PKTS_1024_TO_1514_BYTES",

    # TCP window
    ("flow", "TCP_WIN_MAX_IN"):     "TCP_WIN_MAX_IN",
    ("flow", "TCP_WIN_MAX_OUT"):    "TCP_WIN_MAX_OUT",

    # TCP flags
    ("flow", "CLIENT_TCP_FLAGS"):   "CLIENT_TCP_FLAGS",
    ("flow", "SERVER_TCP_FLAGS"):   "SERVER_TCP_FLAGS",
    ("flow", "TCP_FLAGS"):          "TCP_FLAGS",

    # TTL
    ("flow", "MIN_TTL"):            "MIN_TTL",
    ("flow", "MAX_TTL"):            "MAX_TTL",

    # ICMP
    ("flow", "ICMP_TYPE"):          "ICMP_TYPE",
    ("flow", "ICMP_IPV4_TYPE"):     "ICMP_IPV4_TYPE",

    # DNS
    ("flow", "DNS_QUERY_ID"):       "DNS_QUERY_ID",
    ("flow", "DNS_QUERY_TYPE"):     "DNS_QUERY_TYPE",
    ("flow", "DNS_TTL_ANSWER"):     "DNS_TTL_ANSWER",
    ("flow", "DNS_RESPONSE_CODE"):  "DNS_RESPONSE_CODE",

    # FTP
    ("flow", "FTP_COMMAND_RET_CODE"): "FTP_COMMAND_RET_CODE",

    # HTTP
    ("flow", "HTTP_URL"):           "HTTP_URL",
    ("flow", "HTTP_METHOD"):        "HTTP_METHOD",
    ("flow", "HTTP_USER_AGENT"):    "HTTP_USER_AGENT",

    # L7 — Zeek service string (not nDPI numeric)
    ("flow", "L7_PROTO_STR"):       "L7_PROTO_STR",

    # Timestamps
    ("flow", "FLOW_START_MILLISECONDS"): "FLOW_START_MILLISECONDS",
    ("flow", "FLOW_END_MILLISECONDS"):   "FLOW_END_MILLISECONDS",

    # IAT temporal features (NF-v3 names)
    ("flow", "SRC_TO_DST_IAT_MIN"):     "SRC_TO_DST_IAT_MIN",
    ("flow", "SRC_TO_DST_IAT_MAX"):     "SRC_TO_DST_IAT_MAX",
    ("flow", "SRC_TO_DST_IAT_AVG"):     "SRC_TO_DST_IAT_AVG",
    ("flow", "SRC_TO_DST_IAT_STDDEV"):  "SRC_TO_DST_IAT_STDDEV",
    ("flow", "DST_TO_SRC_IAT_MIN"):     "DST_TO_SRC_IAT_MIN",
    ("flow", "DST_TO_SRC_IAT_MAX"):     "DST_TO_SRC_IAT_MAX",
    ("flow", "DST_TO_SRC_IAT_AVG"):     "DST_TO_SRC_IAT_AVG",
    ("flow", "DST_TO_SRC_IAT_STDDEV"):  "DST_TO_SRC_IAT_STDDEV",
}

# ── NF-v3 output column order ─────────────────────────────────────────────
NF_V3_COLUMNS = [
    "IPV4_SRC_ADDR",
    "L4_SRC_PORT",
    "IPV4_DST_ADDR",
    "L4_DST_PORT",
    "PROTOCOL",
    "IN_BYTES",
    "OUT_BYTES",
    "IN_PKTS",
    "OUT_PKTS",
    "FLOW_DURATION_MILLISECONDS",
    "MIN_IP_PKT_LEN",
    "MAX_IP_PKT_LEN",
    "SRC_TO_DST_SECOND_BYTES",
    "DST_TO_SRC_SECOND_BYTES",
    "SRC_TO_DST_AVG_THROUGHPUT",
    "DST_TO_SRC_AVG_THROUGHPUT",
    "RETRANSMITTED_IN_BYTES",
    "RETRANSMITTED_IN_PKTS",
    "RETRANSMITTED_OUT_BYTES",
    "RETRANSMITTED_OUT_PKTS",
    "NUM_PKTS_UP_TO_128_BYTES",
    "NUM_PKTS_128_TO_256_BYTES",
    "NUM_PKTS_256_TO_512_BYTES",
    "NUM_PKTS_512_TO_1024_BYTES",
    "NUM_PKTS_1024_TO_1514_BYTES",
    "TCP_WIN_MAX_IN",
    "TCP_WIN_MAX_OUT",
    "CLIENT_TCP_FLAGS",
    "SERVER_TCP_FLAGS",
    "TCP_FLAGS",
    "MIN_TTL",
    "MAX_TTL",
    "ICMP_TYPE",
    "ICMP_IPV4_TYPE",
    "DNS_QUERY_ID",
    "DNS_QUERY_TYPE",
    "DNS_TTL_ANSWER",
    "DNS_RESPONSE_CODE",
    "FTP_COMMAND_RET_CODE",
    "L7_PROTO_STR",
    "HTTP_URL",
    "HTTP_METHOD",
    "HTTP_USER_AGENT",
    "FLOW_START_MILLISECONDS",
    "FLOW_END_MILLISECONDS",
    "SRC_TO_DST_IAT_MIN",
    "SRC_TO_DST_IAT_MAX",
    "SRC_TO_DST_IAT_AVG",
    "SRC_TO_DST_IAT_STDDEV",
    "DST_TO_SRC_IAT_MIN",
    "DST_TO_SRC_IAT_MAX",
    "DST_TO_SRC_IAT_AVG",
    "DST_TO_SRC_IAT_STDDEV",
]


def read_zeek_json_log(filepath: str) -> dict:
    """Read a Zeek JSON log file. Returns dict keyed by uid."""
    records = {}
    path = Path(filepath)
    if not path.exists():
        print(f"WARNING: {filepath} not found — skipping.", file=sys.stderr)
        return records

    with open(path, "r", encoding="utf-8") as f:
        for lineno, line in enumerate(f, 1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            try:
                rec = json.loads(line)
                uid = rec.get("uid")
                if uid:
                    records[uid] = rec
            except json.JSONDecodeError as e:
                print(f"WARNING: JSON parse error at {filepath}:{lineno} — {e}",
                      file=sys.stderr)
    return records


def protocol_number(proto_str: str) -> int:
    """Convert Zeek proto string to IANA protocol number."""
    mapping = {
        "tcp":  6,
        "udp":  17,
        "icmp": 1,
        "icmp6": 58,
        "sctp": 132,
        "gre":  47,
        "esp":  50,
    }
    return mapping.get(proto_str.lower(), 0)


def merge_records(flow_rec: dict, conn_rec: dict, label: str = None) -> dict:
    """
    Merge one flowmeter.log record with its matching conn.log record.
    Returns a dict with NF-v3 column names in standard order.
    """
    row = {}

    # ── Flow identity from conn.log ───────────────────────────────────────
    row["IPV4_SRC_ADDR"] = conn_rec.get("id.orig_h", "")
    row["L4_SRC_PORT"]   = conn_rec.get("id.orig_p", 0)
    row["IPV4_DST_ADDR"] = conn_rec.get("id.resp_h", "")
    row["L4_DST_PORT"]   = conn_rec.get("id.resp_p", 0)

    # Protocol — convert string to IANA integer
    proto_str = conn_rec.get("proto", "")
    row["PROTOCOL"] = protocol_number(proto_str)

    # ── Computed fields ───────────────────────────────────────────────────
    # FLOW_DURATION_MILLISECONDS — convert flow_duration (seconds) to ms
    dur_sec = float(flow_rec.get("flow_duration", 0.0))
    row["FLOW_DURATION_MILLISECONDS"] = round(dur_sec * 1000.0, 3)

    # ── Direct NF-v3 fields from flowmeter.log ────────────────────────────
    nf_flow_fields = [
        "IN_BYTES", "OUT_BYTES", "IN_PKTS", "OUT_PKTS",
        "MIN_IP_PKT_LEN", "MAX_IP_PKT_LEN",
        "SRC_TO_DST_SECOND_BYTES", "DST_TO_SRC_SECOND_BYTES",
        "SRC_TO_DST_AVG_THROUGHPUT", "DST_TO_SRC_AVG_THROUGHPUT",
        "RETRANSMITTED_IN_BYTES", "RETRANSMITTED_IN_PKTS",
        "RETRANSMITTED_OUT_BYTES", "RETRANSMITTED_OUT_PKTS",
        "NUM_PKTS_UP_TO_128_BYTES", "NUM_PKTS_128_TO_256_BYTES",
        "NUM_PKTS_256_TO_512_BYTES", "NUM_PKTS_512_TO_1024_BYTES",
        "NUM_PKTS_1024_TO_1514_BYTES",
        "TCP_WIN_MAX_IN", "TCP_WIN_MAX_OUT",
        "CLIENT_TCP_FLAGS", "SERVER_TCP_FLAGS", "TCP_FLAGS",
        "MIN_TTL", "MAX_TTL",
        "ICMP_TYPE", "ICMP_IPV4_TYPE",
        "DNS_QUERY_ID", "DNS_QUERY_TYPE", "DNS_TTL_ANSWER", "DNS_RESPONSE_CODE",
        "FTP_COMMAND_RET_CODE",
        "HTTP_URL", "HTTP_METHOD", "HTTP_USER_AGENT",
        "L7_PROTO_STR",
        "FLOW_START_MILLISECONDS", "FLOW_END_MILLISECONDS",
        "SRC_TO_DST_IAT_MIN", "SRC_TO_DST_IAT_MAX",
        "SRC_TO_DST_IAT_AVG", "SRC_TO_DST_IAT_STDDEV",
        "DST_TO_SRC_IAT_MIN", "DST_TO_SRC_IAT_MAX",
        "DST_TO_SRC_IAT_AVG", "DST_TO_SRC_IAT_STDDEV",
    ]
    for field in nf_flow_fields:
        row[field] = flow_rec.get(field, 0)

    # ── Optional label ────────────────────────────────────────────────────
    if label is not None:
        row["Label"] = label

    return row


def main():
    parser = argparse.ArgumentParser(
        description="Merge Zeek flowmeter.log + conn.log into NF-v3 CSV"
    )
    parser.add_argument("--flowmeter", default="flowmeter.log",
                        help="Path to flowmeter.log (default: flowmeter.log)")
    parser.add_argument("--conn", default="conn.log",
                        help="Path to conn.log (default: conn.log)")
    parser.add_argument("--output", default="nf_features.csv",
                        help="Output CSV path (default: nf_features.csv)")
    parser.add_argument("--label", default=None,
                        help="Optional Label value added to every row "
                             "(e.g., Benign, BruteForce, DDoS)")
    args = parser.parse_args()

    print(f"Reading flowmeter.log from: {args.flowmeter}")
    flow_records = read_zeek_json_log(args.flowmeter)
    print(f"  → {len(flow_records):,} flow records loaded")

    print(f"Reading conn.log from:      {args.conn}")
    conn_records = read_zeek_json_log(args.conn)
    print(f"  → {len(conn_records):,} conn records loaded")

    # ── Merge ─────────────────────────────────────────────────────────────
    merged = []
    unmatched = 0
    for uid, flow_rec in flow_records.items():
        conn_rec = conn_records.get(uid, {})
        if not conn_rec:
            unmatched += 1
        row = merge_records(flow_rec, conn_rec, label=args.label)
        merged.append(row)

    print(f"\nMerge complete:")
    print(f"  Total rows:      {len(merged):,}")
    print(f"  Unmatched flows: {unmatched:,} "
          f"(flowmeter records with no conn.log match)")

    if not merged:
        print("ERROR: No records to write. Check that both logs are non-empty "
              "and in JSON format (redef LogAscii::use_json = T).")
        sys.exit(1)

    # ── Write CSV ─────────────────────────────────────────────────────────
    columns = NF_V3_COLUMNS.copy()
    if args.label is not None:
        columns.append("Label")

    with open(args.output, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=columns, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(merged)

    print(f"\nOutput written to: {args.output}")
    print(f"Columns:           {len(columns)}")

    # ── Quick sanity check — print first row ─────────────────────────────
    if merged:
        print("\nFirst row preview:")
        first = merged[0]
        for col in columns[:10]:
            print(f"  {col:35s} = {first.get(col, '')}")
        print(f"  ... ({len(columns) - 10} more columns)")


if __name__ == "__main__":
    main()
