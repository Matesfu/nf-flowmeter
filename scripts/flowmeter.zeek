##! =============================================================================
##! flowmeter.zeek  —  Extended NF-CSE-CIC-IDS2018-v3 Feature Extractor
##! =============================================================================
##!
##! Original:  zeek-flowmeter (https://github.com/zeek-flowmeter/zeek-flowmeter)
##! Extended:  NF-v3 NetFlow v9 feature parity for IDS/IPS model inference
##!
##! This script extends the original zeek-flowmeter with the following
##! NF-CSE-CIC-IDS2018-v3 features not present in the original:
##!
##!   NEW — IP/Transport layer (per-packet tracking):
##!     MIN_TTL, MAX_TTL
##!     RETRANSMITTED_IN_BYTES, RETRANSMITTED_IN_PKTS
##!     RETRANSMITTED_OUT_BYTES, RETRANSMITTED_OUT_PKTS
##!     NUM_PKTS_UP_TO_128_BYTES
##!     NUM_PKTS_128_TO_256_BYTES
##!     NUM_PKTS_256_TO_512_BYTES
##!     NUM_PKTS_512_TO_1024_BYTES
##!     NUM_PKTS_1024_TO_1514_BYTES
##!     TCP_WIN_MAX_IN, TCP_WIN_MAX_OUT
##!     CLIENT_TCP_FLAGS (combined bitmask, originator direction)
##!     SERVER_TCP_FLAGS (combined bitmask, responder direction)
##!     TCP_FLAGS        (combined bitmask, both directions)
##!     IN_BYTES  (IP-level bytes, src->dst)
##!     OUT_BYTES (IP-level bytes, dst->src)
##!     MIN_IP_PKT_LEN (full IP packet including headers)
##!     MAX_IP_PKT_LEN (full IP packet including headers)
##!     SRC_TO_DST_SECOND_BYTES
##!     DST_TO_SRC_SECOND_BYTES
##!     SRC_TO_DST_AVG_THROUGHPUT
##!     DST_TO_SRC_AVG_THROUGHPUT
##!
##!   NEW — ICMP (via Zeek ICMP analyzer):
##!     ICMP_TYPE
##!     ICMP_IPV4_TYPE
##!
##!   NEW — Application layer (via Zeek protocol analyzers):
##!     DNS_QUERY_ID, DNS_QUERY_TYPE, DNS_TTL_ANSWER, DNS_RESPONSE_CODE
##!     FTP_COMMAND_RET_CODE
##!     HTTP_URL, HTTP_METHOD, HTTP_USER_AGENT
##!
##!   NOTE — L7_PROTO (nDPI numeric ID) is NOT implemented here.
##!   Zeek's conn$service string is written as L7_PROTO_STR for reference.
##!   nDPI numeric IDs require embedding the nDPI C library as a Zeek plugin.
##!
##! Usage (PCAP mode — works on WSL):
##!   zeek -C -r your_traffic.pcap flowmeter
##!
##! Output logs:
##!   flowmeter.log  — all flow features (original + new NF-v3 fields)
##!   conn.log       — Zeek standard connection log (join key: uid)
##!   dns.log        — DNS transactions
##!   http.log       — HTTP transactions
##!   ftp.log        — FTP transactions
##! =============================================================================

module FlowMeter;

export {

    redef enum Log::ID += { LOG };

    # ── Tuneable parameters ────────────────────────────────────────────────────
    ## Max IAT between packets to be in the same subflow (default 1s)
    option subflow_max_iat: interval = 1sec;

    ## Min packets in a bulk transmission (default 5)
    option bulk_min_length: count = 5;

    ## Max idle time before flow is considered inactive (default 5s)
    option active_timeout: interval = 5sec;

    ## Max gap between bulk packets (default 1s)
    option bulk_timeout: interval = 1sec;

    # ── Helper record types ────────────────────────────────────────────────────
    type statistics_info: record {
        min: double &default=0.0;
        max: double &default=0.0;
        tot: double &default=0.0;
        avg: double &default=0.0;
        std: double &default=0.0;
    };

    type inter_arrival_time: record {
        fwd: statistics_info &default=statistics_info();
        bwd: statistics_info &default=statistics_info();
        flow: statistics_info &default=statistics_info();
    };

    # ── Application layer feature cache records ───────────────────────────────
    type DNS_Features: record {
        query_id:      count   &default=0;
        query_type:    count   &default=0;
        ttl_answer:    count   &default=0;
        response_code: count   &default=0;
    };

    type HTTP_Features: record {
        method:     string &default="";
        url:        string &default="";
        user_agent: string &default="";
    };

    type FTP_Features: record {
        ret_code: count &default=0;
    };

    type ICMP_Features: record {
        icmp_type:      count &default=0;
        icmp_ipv4_type: count &default=0;
    };

    # ── Main feature log record ───────────────────────────────────────────────
    type Features: record {

        # ── Flow identity (from conn.log via uid join) ──────────────────
        uid: string &log;

        # ── Original zeek-flowmeter features ───────────────────────────
        flow_duration:          double          &log &default=0.0;
        fwd_pkts_tot:           count           &log &default=0;
        bwd_pkts_tot:           count           &log &default=0;
        fwd_data_pkts_tot:      count           &log &default=0;
        bwd_data_pkts_tot:      count           &log &default=0;
        fwd_pkts_per_sec:       double          &log &default=0.0;
        bwd_pkts_per_sec:       double          &log &default=0.0;
        flow_pkts_per_sec:      double          &log &default=0.0;
        down_up_ratio:          double          &log &default=0.0;
        fwd_header_size_tot:    count           &log &default=0;
        fwd_header_size_min:    count           &log &default=0;
        fwd_header_size_max:    count           &log &default=0;
        bwd_header_size_tot:    count           &log &default=0;
        bwd_header_size_min:    count           &log &default=0;
        bwd_header_size_max:    count           &log &default=0;

        # Payload size statistics
        fwd_pkts_payload_max:   double          &log &default=0.0;
        fwd_pkts_payload_min:   double          &log &default=0.0;
        fwd_pkts_payload_tot:   double          &log &default=0.0;
        fwd_pkts_payload_avg:   double          &log &default=0.0;
        fwd_pkts_payload_std:   double          &log &default=0.0;
        bwd_pkts_payload_max:   double          &log &default=0.0;
        bwd_pkts_payload_min:   double          &log &default=0.0;
        bwd_pkts_payload_tot:   double          &log &default=0.0;
        bwd_pkts_payload_avg:   double          &log &default=0.0;
        bwd_pkts_payload_std:   double          &log &default=0.0;
        flow_pkts_payload_max:  double          &log &default=0.0;
        flow_pkts_payload_min:  double          &log &default=0.0;
        flow_pkts_payload_tot:  double          &log &default=0.0;
        flow_pkts_payload_avg:  double          &log &default=0.0;
        flow_pkts_payload_std:  double          &log &default=0.0;
        payload_bytes_per_sec:  double          &log &default=0.0;

        # TCP flag counts (original — per-flag counters)
        flow_FIN_flag_count:    count           &log &default=0;
        flow_SYN_flag_count:    count           &log &default=0;
        flow_RST_flag_count:    count           &log &default=0;
        fwd_PSH_flag_count:     count           &log &default=0;
        bwd_PSH_flag_count:     count           &log &default=0;
        flow_ACK_flag_count:    count           &log &default=0;
        fwd_URG_flag_count:     count           &log &default=0;
        bwd_URG_flag_count:     count           &log &default=0;
        flow_CWR_flag_count:    count           &log &default=0;
        flow_ECE_flag_count:    count           &log &default=0;

        # IAT statistics
        fwd_iat_max:            double          &log &default=0.0;
        fwd_iat_min:            double          &log &default=0.0;
        fwd_iat_tot:            double          &log &default=0.0;
        fwd_iat_avg:            double          &log &default=0.0;
        fwd_iat_std:            double          &log &default=0.0;
        bwd_iat_max:            double          &log &default=0.0;
        bwd_iat_min:            double          &log &default=0.0;
        bwd_iat_tot:            double          &log &default=0.0;
        bwd_iat_avg:            double          &log &default=0.0;
        bwd_iat_std:            double          &log &default=0.0;
        flow_iat_max:           double          &log &default=0.0;
        flow_iat_min:           double          &log &default=0.0;
        flow_iat_tot:           double          &log &default=0.0;
        flow_iat_avg:           double          &log &default=0.0;
        flow_iat_std:           double          &log &default=0.0;

        # Subflow features
        fwd_subflow_pkts:       double          &log &default=0.0;
        bwd_subflow_pkts:       double          &log &default=0.0;
        fwd_subflow_bytes:      double          &log &default=0.0;
        bwd_subflow_bytes:      double          &log &default=0.0;

        # Bulk features
        fwd_bulk_bytes:         double          &log &default=0.0;
        bwd_bulk_bytes:         double          &log &default=0.0;
        fwd_bulk_packets:       double          &log &default=0.0;
        bwd_bulk_packets:       double          &log &default=0.0;
        fwd_bulk_rate:          double          &log &default=0.0;
        bwd_bulk_rate:          double          &log &default=0.0;

        # Active / idle time
        active_max:             double          &log &default=0.0;
        active_min:             double          &log &default=0.0;
        active_tot:             double          &log &default=0.0;
        active_avg:             double          &log &default=0.0;
        active_std:             double          &log &default=0.0;
        idle_max:               double          &log &default=0.0;
        idle_min:               double          &log &default=0.0;
        idle_tot:               double          &log &default=0.0;
        idle_avg:               double          &log &default=0.0;
        idle_std:               double          &log &default=0.0;

        # Window sizes (first / last — original zeek-flowmeter)
        fwd_init_window_size:   count           &log &default=0;
        bwd_init_window_size:   count           &log &default=0;
        fwd_last_window_size:   count           &log &default=0;
        bwd_last_window_size:   count           &log &default=0;

        # ── NEW: NF-v3 NetFlow v9 features ─────────────────────────────

        # NF-v3 Byte counts (IP-level, matching nProbe IN_BYTES/OUT_BYTES)
        IN_BYTES:               count           &log &default=0;
        OUT_BYTES:              count           &log &default=0;
        IN_PKTS:                count           &log &default=0;
        OUT_PKTS:               count           &log &default=0;

        # NF-v3 IP packet length (full packet including all headers)
        MIN_IP_PKT_LEN:         count           &log &default=0;
        MAX_IP_PKT_LEN:         count           &log &default=0;

        # NF-v3 Throughput per direction
        SRC_TO_DST_SECOND_BYTES:    double      &log &default=0.0;
        DST_TO_SRC_SECOND_BYTES:    double      &log &default=0.0;
        SRC_TO_DST_AVG_THROUGHPUT:  double      &log &default=0.0;
        DST_TO_SRC_AVG_THROUGHPUT:  double      &log &default=0.0;

        # NF-v3 Retransmission counts
        RETRANSMITTED_IN_BYTES:     count       &log &default=0;
        RETRANSMITTED_IN_PKTS:      count       &log &default=0;
        RETRANSMITTED_OUT_BYTES:    count       &log &default=0;
        RETRANSMITTED_OUT_PKTS:     count       &log &default=0;

        # NF-v3 Packet size histogram bins
        NUM_PKTS_UP_TO_128_BYTES:       count   &log &default=0;
        NUM_PKTS_128_TO_256_BYTES:      count   &log &default=0;
        NUM_PKTS_256_TO_512_BYTES:      count   &log &default=0;
        NUM_PKTS_512_TO_1024_BYTES:     count   &log &default=0;
        NUM_PKTS_1024_TO_1514_BYTES:    count   &log &default=0;

        # NF-v3 TCP window max (over full flow lifetime)
        TCP_WIN_MAX_IN:         count           &log &default=0;
        TCP_WIN_MAX_OUT:        count           &log &default=0;

        # NF-v3 TCP flags as combined bitmask (NetFlow v9 format)
        CLIENT_TCP_FLAGS:       count           &log &default=0;
        SERVER_TCP_FLAGS:       count           &log &default=0;
        TCP_FLAGS:              count           &log &default=0;

        # NF-v3 TTL
        MIN_TTL:                count           &log &default=255;
        MAX_TTL:                count           &log &default=0;

        # NF-v3 ICMP
        ICMP_TYPE:              count           &log &default=0;
        ICMP_IPV4_TYPE:         count           &log &default=0;

        # NF-v3 Application layer — DNS
        DNS_QUERY_ID:           count           &log &default=0;
        DNS_QUERY_TYPE:         count           &log &default=0;
        DNS_TTL_ANSWER:         count           &log &default=0;
        DNS_RESPONSE_CODE:      count           &log &default=0;

        # NF-v3 Application layer — FTP
        FTP_COMMAND_RET_CODE:   count           &log &default=0;

        # NF-v3 Application layer — HTTP
        HTTP_URL:               string          &log &default="";
        HTTP_METHOD:            string          &log &default="";
        HTTP_USER_AGENT:        string          &log &default="";

        # NF-v3 L7 — Zeek service string (nDPI numeric ID not available)
        # Use this for reference / manual mapping to nDPI IDs
        L7_PROTO_STR:           string          &log &default="";

        # NF-v3 Timestamps (milliseconds since epoch)
        FLOW_START_MILLISECONDS:    double      &log &default=0.0;
        FLOW_END_MILLISECONDS:      double      &log &default=0.0;

        # NF-v3 IAT temporal features (NF-v3 naming convention)
        SRC_TO_DST_IAT_MIN:     double          &log &default=0.0;
        SRC_TO_DST_IAT_MAX:     double          &log &default=0.0;
        SRC_TO_DST_IAT_AVG:     double          &log &default=0.0;
        SRC_TO_DST_IAT_STDDEV:  double          &log &default=0.0;
        DST_TO_SRC_IAT_MIN:     double          &log &default=0.0;
        DST_TO_SRC_IAT_MAX:     double          &log &default=0.0;
        DST_TO_SRC_IAT_AVG:     double          &log &default=0.0;
        DST_TO_SRC_IAT_STDDEV:  double          &log &default=0.0;
    };
}

# =============================================================================
# Internal per-flow state tables
# =============================================================================

# Packet count per direction
global packet_count:        table[string] of table[string] of count;

# Payload size vectors per direction
global payload_fwd:         table[string] of vector of count;
global payload_bwd:         table[string] of vector of count;

# Header size vectors per direction
global header_fwd:          table[string] of vector of count;
global header_bwd:          table[string] of vector of count;

# IAT tracking — last seen packet time per direction
global last_pkt_time_fwd:   table[string] of time;
global last_pkt_time_bwd:   table[string] of time;
global last_pkt_time_flow:  table[string] of time;

# IAT accumulation vectors
global iat_fwd:             table[string] of vector of double;
global iat_bwd:             table[string] of vector of double;
global iat_flow:            table[string] of vector of double;

# TCP flag counts
global flag_count:          table[string] of table[string] of count;

# TCP flag bitmasks (NetFlow combined byte format)
global tcp_flags_client:    table[string] of count;
global tcp_flags_server:    table[string] of count;

# TCP window max per direction
global tcp_win_max_in:      table[string] of count;
global tcp_win_max_out:     table[string] of count;

# TCP window first/last
global tcp_win_init_fwd:    table[string] of count;
global tcp_win_init_bwd:    table[string] of count;
global tcp_win_last_fwd:    table[string] of count;
global tcp_win_last_bwd:    table[string] of count;

# IP packet length (full packet including all headers)
global ip_pkt_len_min:      table[string] of count;
global ip_pkt_len_max:      table[string] of count;

# TTL min/max
global ttl_min:             table[string] of count;
global ttl_max:             table[string] of count;

# Retransmission counters
global retrans_in_pkts:     table[string] of count;
global retrans_in_bytes:    table[string] of count;
global retrans_out_pkts:    table[string] of count;
global retrans_out_bytes:   table[string] of count;

# Packet size histogram bins
global hist_up_to_128:      table[string] of count;
global hist_128_256:        table[string] of count;
global hist_256_512:        table[string] of count;
global hist_512_1024:       table[string] of count;
global hist_1024_1514:      table[string] of count;

# Active/idle time tracking
global flow_active_periods: table[string] of vector of double;
global flow_idle_periods:   table[string] of vector of double;
global flow_last_active:    table[string] of time;
global flow_is_active:      table[string] of bool;

# Subflow tracking
global subflow_fwd_pkts:    table[string] of vector of count;
global subflow_bwd_pkts:    table[string] of vector of count;
global subflow_fwd_bytes:   table[string] of vector of count;
global subflow_bwd_bytes:   table[string] of vector of count;
global current_subflow_fwd_pkts:    table[string] of count;
global current_subflow_bwd_pkts:    table[string] of count;
global current_subflow_fwd_bytes:   table[string] of count;
global current_subflow_bwd_bytes:   table[string] of count;

# Bulk tracking
global bulk_fwd_bytes:      table[string] of count;
global bulk_fwd_pkts:       table[string] of count;
global bulk_fwd_duration:   table[string] of double;
global bulk_bwd_bytes:      table[string] of count;
global bulk_bwd_pkts:       table[string] of count;
global bulk_bwd_duration:   table[string] of double;
global bulk_fwd_results:    table[string] of vector of double; # [bytes, pkts, duration]
global bulk_bwd_results:    table[string] of vector of double;
global last_bulk_pkt_time_fwd:  table[string] of time;
global last_bulk_pkt_time_bwd:  table[string] of time;
global bulk_fwd_active:     table[string] of bool;
global bulk_bwd_active:     table[string] of bool;

# Data packet tracking (packets with payload)
global data_pkt_fwd:        table[string] of count;
global data_pkt_bwd:        table[string] of count;

# Flow start time
global flow_start_time:     table[string] of time;

# Application layer feature caches (keyed by uid)
global dns_cache:           table[string] of DNS_Features;
global http_cache:          table[string] of HTTP_Features;
global ftp_cache:           table[string] of FTP_Features;
global icmp_cache:          table[string] of ICMP_Features;

# =============================================================================
# Helper functions
# =============================================================================

function generate_stats(vec: vector of double): statistics_info
    {
    local stat = statistics_info($min=0.0, $max=0.0, $tot=0.0, $avg=0.0, $std=0.0);
    if ( |vec| == 0 ) return stat;

    stat$min = vec[0];
    stat$max = vec[0];
    local sum: double = 0.0;
    for ( i in vec )
        {
        local v = vec[i];
        sum += v;
        if ( v < stat$min ) stat$min = v;
        if ( v > stat$max ) stat$max = v;
        }
    stat$tot = sum;
    stat$avg = sum / |vec|;

    local variance: double = 0.0;
    for ( i in vec )
        {
        local diff = vec[i] - stat$avg;
        variance += diff * diff;
        }
    stat$std = sqrt(variance / |vec|);
    return stat;
    }

function generate_stats_count(vec: vector of count): statistics_info
    {
    local dvec: vector of double = vector();
    for ( i in vec )
        dvec += vector(vec[i] + 0.0);
    return generate_stats(dvec);
    }

function init_flow(uid: string, ts: time)
    {
    packet_count[uid]           = table(["fwd"] = 0, ["bwd"] = 0);
    payload_fwd[uid]            = vector();
    payload_bwd[uid]            = vector();
    header_fwd[uid]             = vector();
    header_bwd[uid]             = vector();
    iat_fwd[uid]                = vector();
    iat_bwd[uid]                = vector();
    iat_flow[uid]               = vector();

    flag_count[uid] = table(
        ["FIN"] = 0, ["SYN"] = 0, ["RST"] = 0, ["ACK"] = 0,
        ["fwd,PSH"] = 0, ["bwd,PSH"] = 0,
        ["fwd,URG"] = 0, ["bwd,URG"] = 0,
        ["CWR"] = 0, ["ECE"] = 0
    );

    tcp_flags_client[uid]       = 0;
    tcp_flags_server[uid]       = 0;
    tcp_win_max_in[uid]         = 0;
    tcp_win_max_out[uid]        = 0;
    tcp_win_init_fwd[uid]       = 0;
    tcp_win_init_bwd[uid]       = 0;
    tcp_win_last_fwd[uid]       = 0;
    tcp_win_last_bwd[uid]       = 0;
    ip_pkt_len_min[uid]         = 65535;
    ip_pkt_len_max[uid]         = 0;
    ttl_min[uid]                = 255;
    ttl_max[uid]                = 0;
    retrans_in_pkts[uid]        = 0;
    retrans_in_bytes[uid]       = 0;
    retrans_out_pkts[uid]       = 0;
    retrans_out_bytes[uid]      = 0;
    hist_up_to_128[uid]         = 0;
    hist_128_256[uid]           = 0;
    hist_256_512[uid]           = 0;
    hist_512_1024[uid]          = 0;
    hist_1024_1514[uid]         = 0;

    flow_active_periods[uid]    = vector();
    flow_idle_periods[uid]      = vector();
    flow_last_active[uid]       = ts;
    flow_is_active[uid]         = T;

    subflow_fwd_pkts[uid]       = vector();
    subflow_bwd_pkts[uid]       = vector();
    subflow_fwd_bytes[uid]      = vector();
    subflow_bwd_bytes[uid]      = vector();
    current_subflow_fwd_pkts[uid]  = 0;
    current_subflow_bwd_pkts[uid]  = 0;
    current_subflow_fwd_bytes[uid] = 0;
    current_subflow_bwd_bytes[uid] = 0;

    bulk_fwd_bytes[uid]         = 0;
    bulk_fwd_pkts[uid]          = 0;
    bulk_fwd_duration[uid]      = 0.0;
    bulk_bwd_bytes[uid]         = 0;
    bulk_bwd_pkts[uid]          = 0;
    bulk_bwd_duration[uid]      = 0.0;
    bulk_fwd_results[uid]       = vector();
    bulk_bwd_results[uid]       = vector();
    bulk_fwd_active[uid]        = F;
    bulk_bwd_active[uid]        = F;

    data_pkt_fwd[uid]           = 0;
    data_pkt_bwd[uid]           = 0;
    flow_start_time[uid]        = ts;
    }

function cleanup_flow(uid: string)
    {
    delete packet_count[uid];
    delete payload_fwd[uid];
    delete payload_bwd[uid];
    delete header_fwd[uid];
    delete header_bwd[uid];
    delete iat_fwd[uid];
    delete iat_bwd[uid];
    delete iat_flow[uid];
    delete flag_count[uid];
    delete tcp_flags_client[uid];
    delete tcp_flags_server[uid];
    delete tcp_win_max_in[uid];
    delete tcp_win_max_out[uid];
    delete tcp_win_init_fwd[uid];
    delete tcp_win_init_bwd[uid];
    delete tcp_win_last_fwd[uid];
    delete tcp_win_last_bwd[uid];
    delete ip_pkt_len_min[uid];
    delete ip_pkt_len_max[uid];
    delete ttl_min[uid];
    delete ttl_max[uid];
    delete retrans_in_pkts[uid];
    delete retrans_in_bytes[uid];
    delete retrans_out_pkts[uid];
    delete retrans_out_bytes[uid];
    delete hist_up_to_128[uid];
    delete hist_128_256[uid];
    delete hist_256_512[uid];
    delete hist_512_1024[uid];
    delete hist_1024_1514[uid];
    delete flow_active_periods[uid];
    delete flow_idle_periods[uid];
    delete flow_last_active[uid];
    delete flow_is_active[uid];
    delete subflow_fwd_pkts[uid];
    delete subflow_bwd_pkts[uid];
    delete subflow_fwd_bytes[uid];
    delete subflow_bwd_bytes[uid];
    delete current_subflow_fwd_pkts[uid];
    delete current_subflow_bwd_pkts[uid];
    delete current_subflow_fwd_bytes[uid];
    delete current_subflow_bwd_bytes[uid];
    delete bulk_fwd_bytes[uid];
    delete bulk_fwd_pkts[uid];
    delete bulk_fwd_duration[uid];
    delete bulk_bwd_bytes[uid];
    delete bulk_bwd_pkts[uid];
    delete bulk_bwd_duration[uid];
    delete bulk_fwd_results[uid];
    delete bulk_bwd_results[uid];
    delete bulk_fwd_active[uid];
    delete bulk_bwd_active[uid];
    delete data_pkt_fwd[uid];
    delete data_pkt_bwd[uid];
    delete flow_start_time[uid];
    if ( uid in last_pkt_time_fwd ) delete last_pkt_time_fwd[uid];
    if ( uid in last_pkt_time_bwd ) delete last_pkt_time_bwd[uid];
    if ( uid in last_pkt_time_flow ) delete last_pkt_time_flow[uid];
    if ( uid in dns_cache )  delete dns_cache[uid];
    if ( uid in http_cache ) delete http_cache[uid];
    if ( uid in ftp_cache )  delete ftp_cache[uid];
    if ( uid in icmp_cache ) delete icmp_cache[uid];
    }

# =============================================================================
# Log stream creation
# =============================================================================

event zeek_init()
    {
    Log::create_stream(FlowMeter::LOG,
        [$columns=Features, $path="flowmeter"]);
    }

# =============================================================================
# Connection initialization
# =============================================================================

event new_connection(c: connection)
    {
    init_flow(c$uid, c$start_time);
    }

# =============================================================================
# Per-packet processing — core of all new NF-v3 features
# =============================================================================

event new_packet(c: connection, p: pkt_hdr) &priority=5
    {
    local uid = c$uid;

    if ( uid !in packet_count ) return;

    local ts = network_time();
    local is_orig = (p?$ip &&
                     p$ip$src == c$id$orig_h &&
                     p$ip$dst == c$id$resp_h);

    # ── Direction assignment ─────────────────────────────────────────────────
    local dir = is_orig ? "fwd" : "bwd";

    # ── Packet counts ────────────────────────────────────────────────────────
    packet_count[uid][dir] += 1;

    # ── IP-level packet length (full packet including all headers) ───────────
    local full_pkt_len: count = 0;
    if ( p?$ip )
        {
        full_pkt_len = p$ip$len;
        if ( full_pkt_len < ip_pkt_len_min[uid] )
            ip_pkt_len_min[uid] = full_pkt_len;
        if ( full_pkt_len > ip_pkt_len_max[uid] )
            ip_pkt_len_max[uid] = full_pkt_len;
        }

    # ── TTL min/max (NF-v3: MIN_TTL, MAX_TTL) ───────────────────────────────
    if ( p?$ip )
        {
        local ttl = p$ip$ttl;
        if ( ttl < ttl_min[uid] ) ttl_min[uid] = ttl;
        if ( ttl > ttl_max[uid] ) ttl_max[uid] = ttl;
        }

    # ── Packet size histogram bins (NF-v3 format) ────────────────────────────
    if ( full_pkt_len > 0 )
        {
        if      ( full_pkt_len <= 128  ) hist_up_to_128[uid]  += 1;
        else if ( full_pkt_len <= 256  ) hist_128_256[uid]    += 1;
        else if ( full_pkt_len <= 512  ) hist_256_512[uid]    += 1;
        else if ( full_pkt_len <= 1024 ) hist_512_1024[uid]   += 1;
        else                             hist_1024_1514[uid]  += 1;
        }

    # ── TCP-specific per-packet features ────────────────────────────────────
    if ( p?$tcp )
        {
        local tcp_flags_byte = p$tcp$flags;

        # Combined bitmask flags (NF-v3: CLIENT_TCP_FLAGS / SERVER_TCP_FLAGS)
        if ( is_orig )
            tcp_flags_client[uid] = tcp_flags_client[uid] | tcp_flags_byte;
        else
            tcp_flags_server[uid] = tcp_flags_server[uid] | tcp_flags_byte;

        # TCP window max (NF-v3: TCP_WIN_MAX_IN / TCP_WIN_MAX_OUT)
        local win = p$tcp$win;
        if ( is_orig )
            {
            if ( win > tcp_win_max_in[uid] )
                tcp_win_max_in[uid] = win;
            # Track first and last window size (original zeek-flowmeter)
            if ( packet_count[uid]["fwd"] == 1 )
                tcp_win_init_fwd[uid] = win;
            tcp_win_last_fwd[uid] = win;
            }
        else
            {
            if ( win > tcp_win_max_out[uid] )
                tcp_win_max_out[uid] = win;
            if ( packet_count[uid]["bwd"] == 1 )
                tcp_win_init_bwd[uid] = win;
            tcp_win_last_bwd[uid] = win;
            }

        # Per-flag counts (original zeek-flowmeter style)
        # FIN = 0x01, SYN = 0x02, RST = 0x04, PSH = 0x08
        # ACK = 0x10, URG = 0x20, ECE = 0x40, CWR = 0x80
        if ( tcp_flags_byte & 0x01 != 0 ) flag_count[uid]["FIN"] += 1;
        if ( tcp_flags_byte & 0x02 != 0 ) flag_count[uid]["SYN"] += 1;
        if ( tcp_flags_byte & 0x04 != 0 ) flag_count[uid]["RST"] += 1;
        if ( tcp_flags_byte & 0x10 != 0 ) flag_count[uid]["ACK"] += 1;
        if ( tcp_flags_byte & 0x40 != 0 ) flag_count[uid]["ECE"] += 1;
        if ( tcp_flags_byte & 0x80 != 0 ) flag_count[uid]["CWR"] += 1;
        if ( is_orig )
            {
            if ( tcp_flags_byte & 0x08 != 0 ) flag_count[uid]["fwd,PSH"] += 1;
            if ( tcp_flags_byte & 0x20 != 0 ) flag_count[uid]["fwd,URG"] += 1;
            }
        else
            {
            if ( tcp_flags_byte & 0x08 != 0 ) flag_count[uid]["bwd,PSH"] += 1;
            if ( tcp_flags_byte & 0x20 != 0 ) flag_count[uid]["bwd,URG"] += 1;
            }
        }

    # ── Header and payload size tracking ────────────────────────────────────
    # Payload = full IP length - IP header - transport header
    local ip_hdr_len: count = 0;
    local transport_hdr_len: count = 0;
    if ( p?$ip ) ip_hdr_len = p$ip$hl * 4;
    if ( p?$tcp ) transport_hdr_len = p$tcp$hl * 4;
    else if ( p?$udp ) transport_hdr_len = 8;
    else if ( p?$icmp ) transport_hdr_len = 8;

    local header_size = ip_hdr_len + transport_hdr_len;
    local payload_size: count = 0;
    if ( full_pkt_len > header_size )
        payload_size = full_pkt_len - header_size;

    if ( is_orig )
        {
        header_fwd[uid] += vector(header_size);
        payload_fwd[uid] += vector(payload_size);
        if ( payload_size > 0 ) data_pkt_fwd[uid] += 1;
        }
    else
        {
        header_bwd[uid] += vector(header_size);
        payload_bwd[uid] += vector(payload_size);
        if ( payload_size > 0 ) data_pkt_bwd[uid] += 1;
        }

    # ── IAT (Inter-Arrival Time) calculation ─────────────────────────────────
    if ( is_orig )
        {
        if ( uid in last_pkt_time_fwd )
            {
            local iat_val_fwd = interval_to_double(ts - last_pkt_time_fwd[uid]);
            iat_fwd[uid] += vector(iat_val_fwd);
            }
        last_pkt_time_fwd[uid] = ts;
        }
    else
        {
        if ( uid in last_pkt_time_bwd )
            {
            local iat_val_bwd = interval_to_double(ts - last_pkt_time_bwd[uid]);
            iat_bwd[uid] += vector(iat_val_bwd);
            }
        last_pkt_time_bwd[uid] = ts;
        }

    if ( uid in last_pkt_time_flow )
        {
        local iat_val_flow = interval_to_double(ts - last_pkt_time_flow[uid]);
        iat_flow[uid] += vector(iat_val_flow);
        }
    last_pkt_time_flow[uid] = ts;

    # ── Active / Idle time tracking ──────────────────────────────────────────
    if ( uid in flow_last_active )
        {
        local gap = interval_to_double(ts - flow_last_active[uid]);
        if ( gap > interval_to_double(active_timeout) )
            {
            # Flow was idle — record idle period and start new active period
            flow_idle_periods[uid] += vector(gap);
            if ( flow_is_active[uid] )
                {
                local active_dur = interval_to_double(ts - flow_last_active[uid]);
                flow_active_periods[uid] += vector(active_dur);
                }
            flow_is_active[uid] = T;
            }
        }
    flow_last_active[uid] = ts;

    # ── Subflow tracking ─────────────────────────────────────────────────────
    local prev_ts = uid in last_pkt_time_flow ?
        last_pkt_time_flow[uid] : ts;
    local subflow_gap = interval_to_double(ts - prev_ts);

    if ( subflow_gap > interval_to_double(subflow_max_iat) )
        {
        # End current subflow, save its stats
        subflow_fwd_pkts[uid]  += vector(current_subflow_fwd_pkts[uid]);
        subflow_bwd_pkts[uid]  += vector(current_subflow_bwd_pkts[uid]);
        subflow_fwd_bytes[uid] += vector(current_subflow_fwd_bytes[uid]);
        subflow_bwd_bytes[uid] += vector(current_subflow_bwd_bytes[uid]);
        current_subflow_fwd_pkts[uid]  = 0;
        current_subflow_bwd_pkts[uid]  = 0;
        current_subflow_fwd_bytes[uid] = 0;
        current_subflow_bwd_bytes[uid] = 0;
        }

    if ( is_orig )
        {
        current_subflow_fwd_pkts[uid]  += 1;
        current_subflow_fwd_bytes[uid] += payload_size;
        }
    else
        {
        current_subflow_bwd_pkts[uid]  += 1;
        current_subflow_bwd_bytes[uid] += payload_size;
        }

    # ── Bulk transmission tracking ───────────────────────────────────────────
    if ( payload_size > 0 )
        {
        if ( is_orig )
            {
            if ( bulk_fwd_active[uid] )
                {
                # Check if bulk continues (bwd hasn't transmitted and timeout ok)
                local fwd_gap = uid in last_bulk_pkt_time_fwd ?
                    interval_to_double(ts - last_bulk_pkt_time_fwd[uid]) : 0.0;
                if ( fwd_gap <= interval_to_double(bulk_timeout) )
                    {
                    bulk_fwd_bytes[uid]    += payload_size;
                    bulk_fwd_pkts[uid]     += 1;
                    bulk_fwd_duration[uid] += fwd_gap;
                    }
                else
                    {
                    # End bulk
                    if ( bulk_fwd_pkts[uid] >= bulk_min_length )
                        {
                        bulk_fwd_results[uid] += vector(bulk_fwd_bytes[uid] + 0.0);
                        bulk_fwd_results[uid] += vector(bulk_fwd_pkts[uid] + 0.0);
                        bulk_fwd_results[uid] += vector(bulk_fwd_duration[uid]);
                        }
                    bulk_fwd_bytes[uid]    = payload_size;
                    bulk_fwd_pkts[uid]     = 1;
                    bulk_fwd_duration[uid] = 0.0;
                    }
                }
            else
                {
                bulk_fwd_active[uid]   = T;
                bulk_fwd_bytes[uid]    = payload_size;
                bulk_fwd_pkts[uid]     = 1;
                bulk_fwd_duration[uid] = 0.0;
                }
            last_bulk_pkt_time_fwd[uid] = ts;
            }
        else
            {
            # bwd data packet terminates any active fwd bulk
            if ( bulk_fwd_active[uid] && bulk_fwd_pkts[uid] >= bulk_min_length )
                {
                bulk_fwd_results[uid] += vector(bulk_fwd_bytes[uid] + 0.0);
                bulk_fwd_results[uid] += vector(bulk_fwd_pkts[uid] + 0.0);
                bulk_fwd_results[uid] += vector(bulk_fwd_duration[uid]);
                }
            bulk_fwd_active[uid] = F;

            if ( bulk_bwd_active[uid] )
                {
                local bwd_gap = uid in last_bulk_pkt_time_bwd ?
                    interval_to_double(ts - last_bulk_pkt_time_bwd[uid]) : 0.0;
                if ( bwd_gap <= interval_to_double(bulk_timeout) )
                    {
                    bulk_bwd_bytes[uid]    += payload_size;
                    bulk_bwd_pkts[uid]     += 1;
                    bulk_bwd_duration[uid] += bwd_gap;
                    }
                else
                    {
                    if ( bulk_bwd_pkts[uid] >= bulk_min_length )
                        {
                        bulk_bwd_results[uid] += vector(bulk_bwd_bytes[uid] + 0.0);
                        bulk_bwd_results[uid] += vector(bulk_bwd_pkts[uid] + 0.0);
                        bulk_bwd_results[uid] += vector(bulk_bwd_duration[uid]);
                        }
                    bulk_bwd_bytes[uid]    = payload_size;
                    bulk_bwd_pkts[uid]     = 1;
                    bulk_bwd_duration[uid] = 0.0;
                    }
                }
            else
                {
                bulk_bwd_active[uid]   = T;
                bulk_bwd_bytes[uid]    = payload_size;
                bulk_bwd_pkts[uid]     = 1;
                bulk_bwd_duration[uid] = 0.0;
                }
            last_bulk_pkt_time_bwd[uid] = ts;
            }
        }
    }

# =============================================================================
# TCP retransmission event (NF-v3: RETRANSMITTED_IN/OUT_BYTES/PKTS)
# =============================================================================

event tcp_rexmit(c: connection, is_orig: bool, seq: count,
                 len: count, data_in_flight: count, window: count)
    {
    local uid = c$uid;
    if ( uid !in retrans_in_pkts ) return;

    if ( is_orig )
        {
        retrans_in_pkts[uid]  += 1;
        retrans_in_bytes[uid] += len;
        }
    else
        {
        retrans_out_pkts[uid]  += 1;
        retrans_out_bytes[uid] += len;
        }
    }

# =============================================================================
# ICMP events (NF-v3: ICMP_TYPE, ICMP_IPV4_TYPE)
# =============================================================================

event icmp_sent(c: connection, info: icmp_info)
    {
    local uid = c$uid;
    if ( uid !in icmp_cache )
        icmp_cache[uid] = ICMP_Features();
    # ICMP type is encoded in the "port" fields by Zeek
    # id.orig_p = ICMP type, id.resp_p = ICMP code
    icmp_cache[uid]$icmp_type = info$itype;
    }

event icmp_unreachable(c: connection, info: icmp_info,
                        code: count, context: icmp_context)
    {
    local uid = c$uid;
    if ( uid !in icmp_cache )
        icmp_cache[uid] = ICMP_Features();
    icmp_cache[uid]$icmp_type = 3;  # ICMP type 3 = Destination Unreachable
    # context holds the original IP header that triggered the ICMP error
    if ( ! context$bad_hdr_len )
        icmp_cache[uid]$icmp_ipv4_type = context$proto;
    }

event icmp_time_exceeded(c: connection, info: icmp_info,
                          code: count, context: icmp_context)
    {
    local uid = c$uid;
    if ( uid !in icmp_cache )
        icmp_cache[uid] = ICMP_Features();
    icmp_cache[uid]$icmp_type = 11;  # ICMP type 11 = Time Exceeded
    if ( ! context$bad_hdr_len )
        icmp_cache[uid]$icmp_ipv4_type = context$proto;
    }

event icmp_echo_request(c: connection, info: icmp_info,
                         id: count, seq: count, payload: string)
    {
    local uid = c$uid;
    if ( uid !in icmp_cache )
        icmp_cache[uid] = ICMP_Features();
    icmp_cache[uid]$icmp_type = 8;  # ICMP type 8 = Echo Request
    }

event icmp_echo_reply(c: connection, info: icmp_info,
                       id: count, seq: count, payload: string)
    {
    local uid = c$uid;
    if ( uid !in icmp_cache )
        icmp_cache[uid] = ICMP_Features();
    icmp_cache[uid]$icmp_type = 0;  # ICMP type 0 = Echo Reply
    }

# =============================================================================
# DNS events (NF-v3: DNS_QUERY_ID, DNS_QUERY_TYPE, DNS_TTL_ANSWER,
#                     DNS_RESPONSE_CODE)
# =============================================================================

event dns_request(c: connection, msg: dns_msg, query: string,
                  qtype: count, qclass: count)
    {
    local uid = c$uid;
    if ( uid !in dns_cache )
        dns_cache[uid] = DNS_Features();
    dns_cache[uid]$query_id   = msg$id;
    dns_cache[uid]$query_type = qtype;
    }

event dns_A_reply(c: connection, msg: dns_msg, ans: dns_answer, a: addr)
    {
    local uid = c$uid;
    if ( uid !in dns_cache ) dns_cache[uid] = DNS_Features();
    dns_cache[uid]$ttl_answer    = double_to_count(interval_to_double(ans$TTL));
    dns_cache[uid]$response_code = msg$rcode;
    }

event dns_AAAA_reply(c: connection, msg: dns_msg, ans: dns_answer, a: addr)
    {
    local uid = c$uid;
    if ( uid !in dns_cache ) dns_cache[uid] = DNS_Features();
    dns_cache[uid]$ttl_answer    = double_to_count(interval_to_double(ans$TTL));
    dns_cache[uid]$response_code = msg$rcode;
    }

event dns_MX_reply(c: connection, msg: dns_msg, ans: dns_answer,
                   name: string, preference: count)
    {
    local uid = c$uid;
    if ( uid !in dns_cache ) dns_cache[uid] = DNS_Features();
    dns_cache[uid]$ttl_answer    = double_to_count(interval_to_double(ans$TTL));
    dns_cache[uid]$response_code = msg$rcode;
    }

event dns_NS_reply(c: connection, msg: dns_msg, ans: dns_answer, name: string)
    {
    local uid = c$uid;
    if ( uid !in dns_cache ) dns_cache[uid] = DNS_Features();
    dns_cache[uid]$ttl_answer    = double_to_count(interval_to_double(ans$TTL));
    dns_cache[uid]$response_code = msg$rcode;
    }

event dns_CNAME_reply(c: connection, msg: dns_msg, ans: dns_answer, name: string)
    {
    local uid = c$uid;
    if ( uid !in dns_cache ) dns_cache[uid] = DNS_Features();
    dns_cache[uid]$ttl_answer    = double_to_count(interval_to_double(ans$TTL));
    dns_cache[uid]$response_code = msg$rcode;
    }

event dns_rejected(c: connection, msg: dns_msg, query: string,
                   qtype: count, qclass: count)
    {
    local uid = c$uid;
    if ( uid !in dns_cache ) dns_cache[uid] = DNS_Features();
    dns_cache[uid]$query_id      = msg$id;
    dns_cache[uid]$query_type    = qtype;
    dns_cache[uid]$response_code = msg$rcode;
    }

# =============================================================================
# FTP events (NF-v3: FTP_COMMAND_RET_CODE)
# =============================================================================

event ftp_reply(c: connection, code: count, msg: string, cont_resp: bool)
    {
    local uid = c$uid;
    if ( uid !in ftp_cache )
        ftp_cache[uid] = FTP_Features();
    # Keep the last reply code seen for this connection
    ftp_cache[uid]$ret_code = code;
    }

# =============================================================================
# HTTP events (NF-v3: HTTP_URL, HTTP_METHOD, HTTP_USER_AGENT)
# =============================================================================

event http_request(c: connection, method: string, original_URI: string,
                   unescaped_URI: string, version: string)
    {
    local uid = c$uid;
    if ( uid !in http_cache )
        http_cache[uid] = HTTP_Features();
    http_cache[uid]$method = method;
    http_cache[uid]$url    = original_URI;
    }

event http_header(c: connection, is_orig: bool, name: string, value: string)
    {
    if ( !is_orig ) return;
    local uid = c$uid;
    if ( name == "USER-AGENT" )
        {
        if ( uid !in http_cache )
            http_cache[uid] = HTTP_Features();
        http_cache[uid]$user_agent = value;
        }
    }

# =============================================================================
# Connection close — compute final features and write log
# =============================================================================

event connection_state_remove(c: connection) &priority=-5
    {
    local uid = c$uid;
    if ( uid !in packet_count ) return;

    # ── Basic counts ────────────────────────────────────────────────────────
    local fwd_pkts = packet_count[uid]["fwd"];
    local bwd_pkts = packet_count[uid]["bwd"];
    local total_pkts = fwd_pkts + bwd_pkts;

    # ── Duration ────────────────────────────────────────────────────────────
    local dur: double = 0.0;
    if ( c?$duration )
        dur = interval_to_double(c$duration);
    else if ( uid in flow_start_time && uid in last_pkt_time_flow )
        dur = interval_to_double(last_pkt_time_flow[uid] - flow_start_time[uid]);

    # ── Packets per second ───────────────────────────────────────────────────
    local fwd_pps: double = 0.0;
    local bwd_pps: double = 0.0;
    local flow_pps: double = 0.0;
    if ( dur > 0.0 )
        {
        fwd_pps  = fwd_pkts / dur;
        bwd_pps  = bwd_pkts / dur;
        flow_pps = total_pkts / dur;
        }

    # ── Down/up ratio ────────────────────────────────────────────────────────
    local down_up: double = 0.0;
    if ( fwd_pkts > 0 )
        down_up = bwd_pkts / (fwd_pkts + 0.0);

    # ── Payload statistics ───────────────────────────────────────────────────
    local fwd_payload_stats = generate_stats_count(payload_fwd[uid]);
    local bwd_payload_stats = generate_stats_count(payload_bwd[uid]);

    local all_payloads: vector of count = vector();
    for ( i in payload_fwd[uid] ) all_payloads += vector(payload_fwd[uid][i]);
    for ( i2 in payload_bwd[uid] ) all_payloads += vector(payload_bwd[uid][i2]);
    local flow_payload_stats = generate_stats_count(all_payloads);

    # ── Header statistics ────────────────────────────────────────────────────
    local fwd_hdr_stats = generate_stats_count(header_fwd[uid]);
    local bwd_hdr_stats = generate_stats_count(header_bwd[uid]);

    # ── Bytes per second (payload) ───────────────────────────────────────────
    local payload_bps: double = 0.0;
    if ( dur > 0.0 )
        payload_bps = flow_payload_stats$tot / dur;

    # ── IAT statistics ───────────────────────────────────────────────────────
    local fwd_iat_stats  = generate_stats(iat_fwd[uid]);
    local bwd_iat_stats  = generate_stats(iat_bwd[uid]);
    local flow_iat_stats = generate_stats(iat_flow[uid]);

    # ── Active/idle time statistics ──────────────────────────────────────────
    local active_stats = generate_stats(flow_active_periods[uid]);
    local idle_stats   = generate_stats(flow_idle_periods[uid]);

    # ── Subflow statistics ───────────────────────────────────────────────────
    # Flush current subflow
    subflow_fwd_pkts[uid]  += vector(current_subflow_fwd_pkts[uid]);
    subflow_bwd_pkts[uid]  += vector(current_subflow_bwd_pkts[uid]);
    subflow_fwd_bytes[uid] += vector(current_subflow_fwd_bytes[uid]);
    subflow_bwd_bytes[uid] += vector(current_subflow_bwd_bytes[uid]);

    local sf_fwd_pkt_stats  = generate_stats_count(subflow_fwd_pkts[uid]);
    local sf_bwd_pkt_stats  = generate_stats_count(subflow_bwd_pkts[uid]);
    local sf_fwd_byte_stats = generate_stats_count(subflow_fwd_bytes[uid]);
    local sf_bwd_byte_stats = generate_stats_count(subflow_bwd_bytes[uid]);

    # ── Bulk statistics ──────────────────────────────────────────────────────
    # Flush active bulks
    if ( bulk_fwd_active[uid] && bulk_fwd_pkts[uid] >= bulk_min_length )
        {
        bulk_fwd_results[uid] += vector(bulk_fwd_bytes[uid] + 0.0);
        bulk_fwd_results[uid] += vector(bulk_fwd_pkts[uid] + 0.0);
        bulk_fwd_results[uid] += vector(bulk_fwd_duration[uid]);
        }
    if ( bulk_bwd_active[uid] && bulk_bwd_pkts[uid] >= bulk_min_length )
        {
        bulk_bwd_results[uid] += vector(bulk_bwd_bytes[uid] + 0.0);
        bulk_bwd_results[uid] += vector(bulk_bwd_pkts[uid] + 0.0);
        bulk_bwd_results[uid] += vector(bulk_bwd_duration[uid]);
        }

    local fwd_bulk_byte_avg:  double = 0.0;
    local fwd_bulk_pkt_avg:   double = 0.0;
    local fwd_bulk_rate_avg:  double = 0.0;
    local bwd_bulk_byte_avg:  double = 0.0;
    local bwd_bulk_pkt_avg:   double = 0.0;
    local bwd_bulk_rate_avg:  double = 0.0;

    local fwd_bulk_vec = bulk_fwd_results[uid];
    local n_fwd_bulk = |fwd_bulk_vec| / 3;
    if ( n_fwd_bulk > 0 )
        {
        local total_fwd_bulk_bytes:  double = 0.0;
        local total_fwd_bulk_pkts:   double = 0.0;
        local total_fwd_bulk_dur:    double = 0.0;
        local k: count = 0;
        while ( k < |fwd_bulk_vec| )
            {
            total_fwd_bulk_bytes += fwd_bulk_vec[k];
            total_fwd_bulk_pkts  += fwd_bulk_vec[k+1];
            total_fwd_bulk_dur   += fwd_bulk_vec[k+2];
            k += 3;
            }
        fwd_bulk_byte_avg = total_fwd_bulk_bytes / n_fwd_bulk;
        fwd_bulk_pkt_avg  = total_fwd_bulk_pkts  / n_fwd_bulk;
        if ( total_fwd_bulk_dur > 0.0 )
            fwd_bulk_rate_avg = total_fwd_bulk_bytes / total_fwd_bulk_dur;
        }

    local bwd_bulk_vec = bulk_bwd_results[uid];
    local n_bwd_bulk = |bwd_bulk_vec| / 3;
    if ( n_bwd_bulk > 0 )
        {
        local total_bwd_bulk_bytes:  double = 0.0;
        local total_bwd_bulk_pkts:   double = 0.0;
        local total_bwd_bulk_dur:    double = 0.0;
        local j: count = 0;
        while ( j < |bwd_bulk_vec| )
            {
            total_bwd_bulk_bytes += bwd_bulk_vec[j];
            total_bwd_bulk_pkts  += bwd_bulk_vec[j+1];
            total_bwd_bulk_dur   += bwd_bulk_vec[j+2];
            j += 3;
            }
        bwd_bulk_byte_avg = total_bwd_bulk_bytes / n_bwd_bulk;
        bwd_bulk_pkt_avg  = total_bwd_bulk_pkts  / n_bwd_bulk;
        if ( total_bwd_bulk_dur > 0.0 )
            bwd_bulk_rate_avg = total_bwd_bulk_bytes / total_bwd_bulk_dur;
        }

    # ── NF-v3: IP-level byte counts (from conn record) ───────────────────────
    local in_bytes:  count = 0;
    local out_bytes: count = 0;
    if ( c?$conn )
        {
        if ( c$conn?$orig_ip_bytes ) in_bytes  = c$conn$orig_ip_bytes;
        if ( c$conn?$resp_ip_bytes ) out_bytes = c$conn$resp_ip_bytes;
        }

    # ── NF-v3: Per-direction throughput ─────────────────────────────────────
    local src_dst_sec_bytes:  double = 0.0;
    local dst_src_sec_bytes:  double = 0.0;
    local src_dst_avg_tput:   double = 0.0;
    local dst_src_avg_tput:   double = 0.0;
    if ( dur > 0.0 )
        {
        src_dst_sec_bytes = fwd_payload_stats$tot / dur;
        dst_src_sec_bytes = bwd_payload_stats$tot / dur;
        src_dst_avg_tput  = in_bytes  / dur;
        dst_src_avg_tput  = out_bytes / dur;
        }

    # ── NF-v3: Combined TCP flag bitmask ────────────────────────────────────
    local tcp_flags_combined: count = 0;
    if ( uid in tcp_flags_client )
        tcp_flags_combined = tcp_flags_client[uid] | tcp_flags_server[uid];

    # ── NF-v3: Flow timestamps (milliseconds) ───────────────────────────────
    local flow_start_ms: double = 0.0;
    local flow_end_ms:   double = 0.0;
    if ( uid in flow_start_time )
        flow_start_ms = time_to_double(flow_start_time[uid]) * 1000.0;
    flow_end_ms = flow_start_ms + (dur * 1000.0);

    # ── NF-v3: L7 protocol string (Zeek service — not nDPI numeric ID) ───────
    local l7_str: string = "";
    if ( c$conn?$service && c$conn$service != "" )
        l7_str = c$conn$service;

    # ── NF-v3: Application layer features ────────────────────────────────────
    local dns_qid:  count  = 0;
    local dns_qtyp: count  = 0;
    local dns_ttl:  count  = 0;
    local dns_rcode: count = 0;
    if ( uid in dns_cache )
        {
        dns_qid   = dns_cache[uid]$query_id;
        dns_qtyp  = dns_cache[uid]$query_type;
        dns_ttl   = dns_cache[uid]$ttl_answer;
        dns_rcode = dns_cache[uid]$response_code;
        }

    local ftp_code: count = 0;
    if ( uid in ftp_cache )
        ftp_code = ftp_cache[uid]$ret_code;

    local http_method:  string = "";
    local http_url:     string = "";
    local http_ua:      string = "";
    if ( uid in http_cache )
        {
        http_method = http_cache[uid]$method;
        http_url    = http_cache[uid]$url;
        http_ua     = http_cache[uid]$user_agent;
        }

    local icmp_type:      count = 0;
    local icmp_ipv4_type: count = 0;
    if ( uid in icmp_cache )
        {
        icmp_type      = icmp_cache[uid]$icmp_type;
        icmp_ipv4_type = icmp_cache[uid]$icmp_ipv4_type;
        }
    # For ICMP flows, Zeek encodes type in id.orig_p
    else if ( c$conn?$proto && c$conn$proto == icmp )
        icmp_type = port_to_count(c$id$orig_p);

    # ── Min/Max TTL safety check (if no IP packets seen, reset to 0) ─────────
    local min_ttl_val: count = 0;
    local max_ttl_val: count = 0;
    if ( uid in ttl_min && ttl_min[uid] < 255 )
        min_ttl_val = ttl_min[uid];
    if ( uid in ttl_max )
        max_ttl_val = ttl_max[uid];

    # ── Write log record ─────────────────────────────────────────────────────
    local rec = Features(
        $uid                        = uid,

        # Original zeek-flowmeter features
        $flow_duration              = dur,
        $fwd_pkts_tot               = fwd_pkts,
        $bwd_pkts_tot               = bwd_pkts,
        $fwd_data_pkts_tot          = data_pkt_fwd[uid],
        $bwd_data_pkts_tot          = data_pkt_bwd[uid],
        $fwd_pkts_per_sec           = fwd_pps,
        $bwd_pkts_per_sec           = bwd_pps,
        $flow_pkts_per_sec          = flow_pps,
        $down_up_ratio              = down_up,
        $fwd_header_size_tot        = double_to_count(fwd_hdr_stats$tot),
        $fwd_header_size_min        = double_to_count(fwd_hdr_stats$min),
        $fwd_header_size_max        = double_to_count(fwd_hdr_stats$max),
        $bwd_header_size_tot        = double_to_count(bwd_hdr_stats$tot),
        $bwd_header_size_min        = double_to_count(bwd_hdr_stats$min),
        $bwd_header_size_max        = double_to_count(bwd_hdr_stats$max),

        $fwd_pkts_payload_max       = fwd_payload_stats$max,
        $fwd_pkts_payload_min       = fwd_payload_stats$min,
        $fwd_pkts_payload_tot       = fwd_payload_stats$tot,
        $fwd_pkts_payload_avg       = fwd_payload_stats$avg,
        $fwd_pkts_payload_std       = fwd_payload_stats$std,
        $bwd_pkts_payload_max       = bwd_payload_stats$max,
        $bwd_pkts_payload_min       = bwd_payload_stats$min,
        $bwd_pkts_payload_tot       = bwd_payload_stats$tot,
        $bwd_pkts_payload_avg       = bwd_payload_stats$avg,
        $bwd_pkts_payload_std       = bwd_payload_stats$std,
        $flow_pkts_payload_max      = flow_payload_stats$max,
        $flow_pkts_payload_min      = flow_payload_stats$min,
        $flow_pkts_payload_tot      = flow_payload_stats$tot,
        $flow_pkts_payload_avg      = flow_payload_stats$avg,
        $flow_pkts_payload_std      = flow_payload_stats$std,
        $payload_bytes_per_sec      = payload_bps,

        $flow_FIN_flag_count        = flag_count[uid]["FIN"],
        $flow_SYN_flag_count        = flag_count[uid]["SYN"],
        $flow_RST_flag_count        = flag_count[uid]["RST"],
        $fwd_PSH_flag_count         = flag_count[uid]["fwd,PSH"],
        $bwd_PSH_flag_count         = flag_count[uid]["bwd,PSH"],
        $flow_ACK_flag_count        = flag_count[uid]["ACK"],
        $fwd_URG_flag_count         = flag_count[uid]["fwd,URG"],
        $bwd_URG_flag_count         = flag_count[uid]["bwd,URG"],
        $flow_CWR_flag_count        = flag_count[uid]["CWR"],
        $flow_ECE_flag_count        = flag_count[uid]["ECE"],

        $fwd_iat_max                = fwd_iat_stats$max,
        $fwd_iat_min                = fwd_iat_stats$min,
        $fwd_iat_tot                = fwd_iat_stats$tot,
        $fwd_iat_avg                = fwd_iat_stats$avg,
        $fwd_iat_std                = fwd_iat_stats$std,
        $bwd_iat_max                = bwd_iat_stats$max,
        $bwd_iat_min                = bwd_iat_stats$min,
        $bwd_iat_tot                = bwd_iat_stats$tot,
        $bwd_iat_avg                = bwd_iat_stats$avg,
        $bwd_iat_std                = bwd_iat_stats$std,
        $flow_iat_max               = flow_iat_stats$max,
        $flow_iat_min               = flow_iat_stats$min,
        $flow_iat_tot               = flow_iat_stats$tot,
        $flow_iat_avg               = flow_iat_stats$avg,
        $flow_iat_std               = flow_iat_stats$std,

        $fwd_subflow_pkts           = sf_fwd_pkt_stats$avg,
        $bwd_subflow_pkts           = sf_bwd_pkt_stats$avg,
        $fwd_subflow_bytes          = sf_fwd_byte_stats$avg,
        $bwd_subflow_bytes          = sf_bwd_byte_stats$avg,

        $fwd_bulk_bytes             = fwd_bulk_byte_avg,
        $bwd_bulk_bytes             = bwd_bulk_byte_avg,
        $fwd_bulk_packets           = fwd_bulk_pkt_avg,
        $bwd_bulk_packets           = bwd_bulk_pkt_avg,
        $fwd_bulk_rate              = fwd_bulk_rate_avg,
        $bwd_bulk_rate              = bwd_bulk_rate_avg,

        $active_max                 = active_stats$max,
        $active_min                 = active_stats$min,
        $active_tot                 = active_stats$tot,
        $active_avg                 = active_stats$avg,
        $active_std                 = active_stats$std,
        $idle_max                   = idle_stats$max,
        $idle_min                   = idle_stats$min,
        $idle_tot                   = idle_stats$tot,
        $idle_avg                   = idle_stats$avg,
        $idle_std                   = idle_stats$std,

        $fwd_init_window_size       = tcp_win_init_fwd[uid],
        $bwd_init_window_size       = tcp_win_init_bwd[uid],
        $fwd_last_window_size       = tcp_win_last_fwd[uid],
        $bwd_last_window_size       = tcp_win_last_bwd[uid],

        # NF-v3 new features
        $IN_BYTES                   = in_bytes,
        $OUT_BYTES                  = out_bytes,
        $IN_PKTS                    = fwd_pkts,
        $OUT_PKTS                   = bwd_pkts,
        $MIN_IP_PKT_LEN             = ip_pkt_len_min[uid] == 65535 ? 0 : ip_pkt_len_min[uid],
        $MAX_IP_PKT_LEN             = ip_pkt_len_max[uid],
        $SRC_TO_DST_SECOND_BYTES    = src_dst_sec_bytes,
        $DST_TO_SRC_SECOND_BYTES    = dst_src_sec_bytes,
        $SRC_TO_DST_AVG_THROUGHPUT  = src_dst_avg_tput,
        $DST_TO_SRC_AVG_THROUGHPUT  = dst_src_avg_tput,
        $RETRANSMITTED_IN_BYTES     = retrans_in_bytes[uid],
        $RETRANSMITTED_IN_PKTS      = retrans_in_pkts[uid],
        $RETRANSMITTED_OUT_BYTES    = retrans_out_bytes[uid],
        $RETRANSMITTED_OUT_PKTS     = retrans_out_pkts[uid],
        $NUM_PKTS_UP_TO_128_BYTES   = hist_up_to_128[uid],
        $NUM_PKTS_128_TO_256_BYTES  = hist_128_256[uid],
        $NUM_PKTS_256_TO_512_BYTES  = hist_256_512[uid],
        $NUM_PKTS_512_TO_1024_BYTES = hist_512_1024[uid],
        $NUM_PKTS_1024_TO_1514_BYTES = hist_1024_1514[uid],
        $TCP_WIN_MAX_IN             = tcp_win_max_in[uid],
        $TCP_WIN_MAX_OUT            = tcp_win_max_out[uid],
        $CLIENT_TCP_FLAGS           = tcp_flags_client[uid],
        $SERVER_TCP_FLAGS           = tcp_flags_server[uid],
        $TCP_FLAGS                  = tcp_flags_combined,
        $MIN_TTL                    = min_ttl_val,
        $MAX_TTL                    = max_ttl_val,
        $ICMP_TYPE                  = icmp_type,
        $ICMP_IPV4_TYPE             = icmp_ipv4_type,
        $DNS_QUERY_ID               = dns_qid,
        $DNS_QUERY_TYPE             = dns_qtyp,
        $DNS_TTL_ANSWER             = dns_ttl,
        $DNS_RESPONSE_CODE          = dns_rcode,
        $FTP_COMMAND_RET_CODE       = ftp_code,
        $HTTP_URL                   = http_url,
        $HTTP_METHOD                = http_method,
        $HTTP_USER_AGENT            = http_ua,
        $L7_PROTO_STR               = l7_str,
        $FLOW_START_MILLISECONDS    = flow_start_ms,
        $FLOW_END_MILLISECONDS      = flow_end_ms,
        $SRC_TO_DST_IAT_MIN         = fwd_iat_stats$min,
        $SRC_TO_DST_IAT_MAX         = fwd_iat_stats$max,
        $SRC_TO_DST_IAT_AVG         = fwd_iat_stats$avg,
        $SRC_TO_DST_IAT_STDDEV      = fwd_iat_stats$std,
        $DST_TO_SRC_IAT_MIN         = bwd_iat_stats$min,
        $DST_TO_SRC_IAT_MAX         = bwd_iat_stats$max,
        $DST_TO_SRC_IAT_AVG         = bwd_iat_stats$avg,
        $DST_TO_SRC_IAT_STDDEV      = bwd_iat_stats$std
    );

    Log::write(FlowMeter::LOG, rec);
    cleanup_flow(uid);
    }
