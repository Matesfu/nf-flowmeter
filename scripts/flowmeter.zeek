##! =============================================================================
##! flowmeter.zeek  —  NF-CSE-CIC-IDS2018-v3 Feature Extractor (53 features)
##! =============================================================================
##!
##! Extracts exactly the 53 NF-v3 NetFlow v9 features directly from network
##! traffic, matching the column set used by models trained on the University
##! of Queensland NF-v3 dataset series (NF-CSE-CIC-IDS2018-v3 and siblings).
##!
##! All 53 features are written to flowmeter.log in JSON format, one flow per
##! line, with every field name shown alongside its value:
##!
##!   {"IPV4_SRC_ADDR":"10.0.0.1","L4_SRC_PORT":54321,"IPV4_DST_ADDR":...}
##!
##! Usage (PCAP mode — works on WSL):
##!   zeek -C -r your_traffic.pcap flowmeter
##!
##! NOTE — L7_PROTO holds Zeek's service string (e.g. "http", "dns", "ssl")
##! rather than an nDPI numeric ID. Map it in your ML preprocessing if needed.
##! =============================================================================

module FlowMeter;

export {

    redef enum Log::ID += { LOG };

    # ── Application-layer feature caches ──────────────────────────────────────
    type DNS_Features: record {
        query_id:      count &default=0;
        query_type:    count &default=0;
        ttl_answer:    count &default=0;
        response_code: count &default=0;
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

    # ── NF-v3 log record (exactly 53 fields, in canonical order) ─────────────
    type Features: record {

        # 1–5: Flow identity ────────────────────────────────────────────────
        IPV4_SRC_ADDR:      addr    &log;
        L4_SRC_PORT:        count   &log;
        IPV4_DST_ADDR:      addr    &log;
        L4_DST_PORT:        count   &log;
        PROTOCOL:           count   &log;

        # 6–9: Byte / packet counts ─────────────────────────────────────────
        IN_BYTES:           count   &log &default=0;
        OUT_BYTES:          count   &log &default=0;
        IN_PKTS:            count   &log &default=0;
        OUT_PKTS:           count   &log &default=0;

        # 10: Duration ──────────────────────────────────────────────────────
        FLOW_DURATION_MILLISECONDS: double &log &default=0.0;

        # 11–12: IP packet length (full packet incl. all headers) ───────────
        MIN_IP_PKT_LEN:     count   &log &default=0;
        MAX_IP_PKT_LEN:     count   &log &default=0;

        # 13–16: Per-direction throughput ───────────────────────────────────
        SRC_TO_DST_SECOND_BYTES:   double &log &default=0.0;
        DST_TO_SRC_SECOND_BYTES:   double &log &default=0.0;
        SRC_TO_DST_AVG_THROUGHPUT: double &log &default=0.0;
        DST_TO_SRC_AVG_THROUGHPUT: double &log &default=0.0;

        # 17–20: TCP retransmission ─────────────────────────────────────────
        RETRANSMITTED_IN_BYTES:  count &log &default=0;
        RETRANSMITTED_IN_PKTS:   count &log &default=0;
        RETRANSMITTED_OUT_BYTES: count &log &default=0;
        RETRANSMITTED_OUT_PKTS:  count &log &default=0;

        # 21–25: Packet-size histogram ──────────────────────────────────────
        NUM_PKTS_UP_TO_128_BYTES:    count &log &default=0;
        NUM_PKTS_128_TO_256_BYTES:   count &log &default=0;
        NUM_PKTS_256_TO_512_BYTES:   count &log &default=0;
        NUM_PKTS_512_TO_1024_BYTES:  count &log &default=0;
        NUM_PKTS_1024_TO_1514_BYTES: count &log &default=0;

        # 26–27: TCP window max over flow lifetime ──────────────────────────
        TCP_WIN_MAX_IN:     count   &log &default=0;
        TCP_WIN_MAX_OUT:    count   &log &default=0;

        # 28–30: TCP flags as cumulative bitmask (NetFlow v9 format) ────────
        CLIENT_TCP_FLAGS:   count   &log &default=0;
        SERVER_TCP_FLAGS:   count   &log &default=0;
        TCP_FLAGS:          count   &log &default=0;

        # 31–32: TTL ────────────────────────────────────────────────────────
        MIN_TTL:            count   &log &default=0;
        MAX_TTL:            count   &log &default=0;

        # 33–34: ICMP ───────────────────────────────────────────────────────
        ICMP_TYPE:          count   &log &default=0;
        ICMP_IPV4_TYPE:     count   &log &default=0;

        # 35–38: DNS ────────────────────────────────────────────────────────
        DNS_QUERY_ID:       count   &log &default=0;
        DNS_QUERY_TYPE:     count   &log &default=0;
        DNS_TTL_ANSWER:     count   &log &default=0;
        DNS_RESPONSE_CODE:  count   &log &default=0;

        # 39: FTP ───────────────────────────────────────────────────────────
        FTP_COMMAND_RET_CODE: count &log &default=0;

        # 40: L7 protocol (Zeek service string; nDPI numeric not available) ─
        L7_PROTO:           string  &log &default="";

        # 41–43: HTTP ───────────────────────────────────────────────────────
        HTTP_URL:           string  &log &default="";
        HTTP_METHOD:        string  &log &default="";
        HTTP_USER_AGENT:    string  &log &default="";

        # 44–45: Flow timestamps (milliseconds since epoch) ─────────────────
        FLOW_START_MILLISECONDS: double &log &default=0.0;
        FLOW_END_MILLISECONDS:   double &log &default=0.0;

        # 46–53: Inter-arrival-time statistics per direction ────────────────
        SRC_TO_DST_IAT_MIN:    double &log &default=0.0;
        SRC_TO_DST_IAT_MAX:    double &log &default=0.0;
        SRC_TO_DST_IAT_AVG:    double &log &default=0.0;
        SRC_TO_DST_IAT_STDDEV: double &log &default=0.0;
        DST_TO_SRC_IAT_MIN:    double &log &default=0.0;
        DST_TO_SRC_IAT_MAX:    double &log &default=0.0;
        DST_TO_SRC_IAT_AVG:    double &log &default=0.0;
        DST_TO_SRC_IAT_STDDEV: double &log &default=0.0;
    };
}

# =============================================================================
# Per-flow state tables (keyed by connection uid)
# =============================================================================

# Packet counts per direction
global pkt_count_fwd:       table[string] of count;
global pkt_count_bwd:       table[string] of count;

# Payload byte totals per direction (for SECOND_BYTES throughput)
global payload_bytes_fwd:   table[string] of count;
global payload_bytes_bwd:   table[string] of count;

# IP packet length extremes (full packet including headers)
global ip_pkt_len_min:      table[string] of count;
global ip_pkt_len_max:      table[string] of count;

# TTL extremes
global ttl_min:             table[string] of count;
global ttl_max:             table[string] of count;

# Packet-size histogram bins
global hist_up_to_128:      table[string] of count;
global hist_128_256:        table[string] of count;
global hist_256_512:        table[string] of count;
global hist_512_1024:       table[string] of count;
global hist_1024_1514:      table[string] of count;

# TCP flags cumulative bitmask per direction
global tcp_flags_client:    table[string] of count;
global tcp_flags_server:    table[string] of count;

# TCP window max per direction
global tcp_win_max_in:      table[string] of count;
global tcp_win_max_out:     table[string] of count;

# TCP retransmission counters
global retrans_in_pkts:     table[string] of count;
global retrans_in_bytes:    table[string] of count;
global retrans_out_pkts:    table[string] of count;
global retrans_out_bytes:   table[string] of count;

# IAT tracking — packet arrival times & accumulated gaps per direction
global last_pkt_time_fwd:   table[string] of time;
global last_pkt_time_bwd:   table[string] of time;
global iat_fwd:             table[string] of vector of double;
global iat_bwd:             table[string] of vector of double;

# Flow start timestamp
global flow_start_time:     table[string] of time;

# Application-layer feature caches
global dns_cache:           table[string] of DNS_Features;
global http_cache:          table[string] of HTTP_Features;
global ftp_cache:           table[string] of FTP_Features;
global icmp_cache:          table[string] of ICMP_Features;

# =============================================================================
# Helper functions
# =============================================================================

## Convert Zeek transport_proto enum to IANA protocol number.
function proto_to_num(p: transport_proto): count
    {
    switch ( p ) {
        case tcp:          return 6;
        case udp:          return 17;
        case icmp:         return 1;
        case unknown_transport: return 0;
    }
    return 0;
    }

## Compute min / max / avg / population-stddev over a vector of doubles.
## Returns a 4-element vector: [min, max, avg, stddev].
function iat_stats(v: vector of double): vector of double
    {
    if ( |v| == 0 )
        return vector(0.0, 0.0, 0.0, 0.0);

    local vmin = v[0];
    local vmax = v[0];
    local sum  = 0.0;
    for ( i in v )
        {
        local x = v[i];
        sum += x;
        if ( x < vmin ) vmin = x;
        if ( x > vmax ) vmax = x;
        }
    local avg = sum / |v|;

    local var = 0.0;
    for ( j in v )
        {
        local d = v[j] - avg;
        var += d * d;
        }
    local std = sqrt(var / |v|);

    return vector(vmin, vmax, avg, std);
    }

## Initialise all per-flow state when a new connection is first seen.
function init_flow(uid: string, ts: time)
    {
    pkt_count_fwd[uid]     = 0;
    pkt_count_bwd[uid]     = 0;
    payload_bytes_fwd[uid] = 0;
    payload_bytes_bwd[uid] = 0;
    ip_pkt_len_min[uid]    = 65535;
    ip_pkt_len_max[uid]    = 0;
    ttl_min[uid]           = 255;
    ttl_max[uid]           = 0;
    hist_up_to_128[uid]    = 0;
    hist_128_256[uid]      = 0;
    hist_256_512[uid]      = 0;
    hist_512_1024[uid]     = 0;
    hist_1024_1514[uid]    = 0;
    tcp_flags_client[uid]  = 0;
    tcp_flags_server[uid]  = 0;
    tcp_win_max_in[uid]    = 0;
    tcp_win_max_out[uid]   = 0;
    retrans_in_pkts[uid]   = 0;
    retrans_in_bytes[uid]  = 0;
    retrans_out_pkts[uid]  = 0;
    retrans_out_bytes[uid] = 0;
    iat_fwd[uid]           = vector();
    iat_bwd[uid]           = vector();
    flow_start_time[uid]   = ts;
    }

## Release all per-flow state after the log record has been written.
function cleanup_flow(uid: string)
    {
    delete pkt_count_fwd[uid];
    delete pkt_count_bwd[uid];
    delete payload_bytes_fwd[uid];
    delete payload_bytes_bwd[uid];
    delete ip_pkt_len_min[uid];
    delete ip_pkt_len_max[uid];
    delete ttl_min[uid];
    delete ttl_max[uid];
    delete hist_up_to_128[uid];
    delete hist_128_256[uid];
    delete hist_256_512[uid];
    delete hist_512_1024[uid];
    delete hist_1024_1514[uid];
    delete tcp_flags_client[uid];
    delete tcp_flags_server[uid];
    delete tcp_win_max_in[uid];
    delete tcp_win_max_out[uid];
    delete retrans_in_pkts[uid];
    delete retrans_in_bytes[uid];
    delete retrans_out_pkts[uid];
    delete retrans_out_bytes[uid];
    delete iat_fwd[uid];
    delete iat_bwd[uid];
    delete flow_start_time[uid];
    if ( uid in last_pkt_time_fwd ) delete last_pkt_time_fwd[uid];
    if ( uid in last_pkt_time_bwd ) delete last_pkt_time_bwd[uid];
    if ( uid in dns_cache )  delete dns_cache[uid];
    if ( uid in http_cache ) delete http_cache[uid];
    if ( uid in ftp_cache )  delete ftp_cache[uid];
    if ( uid in icmp_cache ) delete icmp_cache[uid];
    }

# =============================================================================
# Log stream creation — force JSON output for flowmeter.log only
# =============================================================================

event zeek_init() &priority=5
    {
    Log::create_stream(FlowMeter::LOG,
        [$columns=Features, $path="flowmeter"]);
    }

event zeek_init() &priority=-5
    {
    # Configure the flowmeter.log writer to emit JSON so every field name
    # appears alongside its value on every line.  This only affects the
    # flowmeter stream — other Zeek logs keep their normal format.
    local f = Log::get_filter(FlowMeter::LOG, "default");
    f$config = table(["use_json"] = "T");
    Log::add_filter(FlowMeter::LOG, f);
    }

# =============================================================================
# Connection lifecycle — initialise state on new connection
# =============================================================================

event new_connection(c: connection)
    {
    init_flow(c$uid, c$start_time);
    }

# =============================================================================
# Per-packet processing — drives most NF-v3 counters
# =============================================================================

event new_packet(c: connection, p: pkt_hdr) &priority=5
    {
    local uid = c$uid;
    if ( uid !in pkt_count_fwd ) return;

    local ts = network_time();

    # Direction: originator → responder is "fwd" (src→dst in NF-v3 terms)
    local is_orig = (p?$ip &&
                     p$ip$src == c$id$orig_h &&
                     p$ip$dst == c$id$resp_h);

    # ── Packet counts ────────────────────────────────────────────────────────
    if ( is_orig )
        pkt_count_fwd[uid] += 1;
    else
        pkt_count_bwd[uid] += 1;

    # ── IP-level packet length (full packet including all headers) ──────────
    local full_pkt_len: count = 0;
    if ( p?$ip )
        {
        full_pkt_len = p$ip$len;
        if ( full_pkt_len < ip_pkt_len_min[uid] )
            ip_pkt_len_min[uid] = full_pkt_len;
        if ( full_pkt_len > ip_pkt_len_max[uid] )
            ip_pkt_len_max[uid] = full_pkt_len;

        # ── TTL extremes ─────────────────────────────────────────────────────
        local ttl = p$ip$ttl;
        if ( ttl < ttl_min[uid] ) ttl_min[uid] = ttl;
        if ( ttl > ttl_max[uid] ) ttl_max[uid] = ttl;
        }

    # ── Packet-size histogram bins ──────────────────────────────────────────
    if ( full_pkt_len > 0 )
        {
        if      ( full_pkt_len <= 128  ) hist_up_to_128[uid]  += 1;
        else if ( full_pkt_len <= 256  ) hist_128_256[uid]    += 1;
        else if ( full_pkt_len <= 512  ) hist_256_512[uid]    += 1;
        else if ( full_pkt_len <= 1024 ) hist_512_1024[uid]   += 1;
        else                             hist_1024_1514[uid]  += 1;
        }

    # ── TCP-specific per-packet features ─────────────────────────────────────
    if ( p?$tcp )
        {
        # Cumulative flag bitmask (NetFlow v9 format)
        # FIN=0x01 SYN=0x02 RST=0x04 PSH=0x08 ACK=0x10 URG=0x20 ECE=0x40 CWR=0x80
        local fbyte = p$tcp$flags;
        if ( is_orig )
            tcp_flags_client[uid] = tcp_flags_client[uid] | fbyte;
        else
            tcp_flags_server[uid] = tcp_flags_server[uid] | fbyte;

        # TCP window max over flow lifetime
        local win = p$tcp$win;
        if ( is_orig )
            {
            if ( win > tcp_win_max_in[uid] )
                tcp_win_max_in[uid] = win;
            }
        else
            {
            if ( win > tcp_win_max_out[uid] )
                tcp_win_max_out[uid] = win;
            }
        }

    # ── Payload byte totals (for SRC_TO_DST / DST_TO_SRC SECOND_BYTES) ──────
    # Payload = full IP length − IP header − transport header
    # Note: p$ip$hl and p$tcp$hl are already in bytes in Zeek (not 4-byte words)
    local ip_hdr_len: count = 0;
    local xport_hdr_len: count = 0;
    if ( p?$ip )   ip_hdr_len    = p$ip$hl;
    if ( p?$tcp )  xport_hdr_len = p$tcp$hl;
    else if ( p?$udp )  xport_hdr_len = 8;
    else if ( p?$icmp ) xport_hdr_len = 8;

    local hdr_total = ip_hdr_len + xport_hdr_len;
    local payload_len: count = 0;
    if ( full_pkt_len > hdr_total )
        payload_len = full_pkt_len - hdr_total;

    if ( is_orig )
        payload_bytes_fwd[uid] += payload_len;
    else
        payload_bytes_bwd[uid] += payload_len;

    # ── Inter-arrival time per direction ─────────────────────────────────────
    if ( is_orig )
        {
        if ( uid in last_pkt_time_fwd )
            iat_fwd[uid] += interval_to_double(ts - last_pkt_time_fwd[uid]);
        last_pkt_time_fwd[uid] = ts;
        }
    else
        {
        if ( uid in last_pkt_time_bwd )
            iat_bwd[uid] += interval_to_double(ts - last_pkt_time_bwd[uid]);
        last_pkt_time_bwd[uid] = ts;
        }
    }

# =============================================================================
# TCP retransmission tracking
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
# ICMP events
# =============================================================================

event icmp_sent(c: connection, info: icmp_info)
    {
    local uid = c$uid;
    if ( uid !in icmp_cache )
        icmp_cache[uid] = ICMP_Features();
    icmp_cache[uid]$icmp_type = info$itype;
    }

event icmp_echo_request(c: connection, info: icmp_info,
                        id: count, seq: count, payload: string)
    {
    local uid = c$uid;
    if ( uid !in icmp_cache )
        icmp_cache[uid] = ICMP_Features();
    icmp_cache[uid]$icmp_type = info$itype;
    }

event icmp_echo_reply(c: connection, info: icmp_info,
                      id: count, seq: count, payload: string)
    {
    local uid = c$uid;
    if ( uid !in icmp_cache )
        icmp_cache[uid] = ICMP_Features();
    icmp_cache[uid]$icmp_type = info$itype;
    }

event icmp_unreachable(c: connection, info: icmp_info,
                       code: count, context: icmp_context)
    {
    local uid = c$uid;
    if ( uid !in icmp_cache )
        icmp_cache[uid] = ICMP_Features();
    icmp_cache[uid]$icmp_type = info$itype;
    # ICMP_IPV4_TYPE = IANA protocol number of the packet that triggered this ICMP.
    # Zeek's context$proto holds the internal enum value, not the IANA number,
    # so derive it from the embedded conn_id port instead.
    if ( ! context$bad_hdr_len )
        icmp_cache[uid]$icmp_ipv4_type =
            proto_to_num(get_port_transport_proto(context$id$resp_p));
    }

event icmp_time_exceeded(c: connection, info: icmp_info,
                         code: count, context: icmp_context)
    {
    local uid = c$uid;
    if ( uid !in icmp_cache )
        icmp_cache[uid] = ICMP_Features();
    icmp_cache[uid]$icmp_type = info$itype;
    if ( ! context$bad_hdr_len )
        icmp_cache[uid]$icmp_ipv4_type =
            proto_to_num(get_port_transport_proto(context$id$resp_p));
    }

# =============================================================================
# DNS events
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

event dns_CNAME_reply(c: connection, msg: dns_msg, ans: dns_answer, name: string)
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
# FTP events
# =============================================================================

event ftp_reply(c: connection, code: count, msg: string, cont_resp: bool)
    {
    local uid = c$uid;
    if ( uid !in ftp_cache )
        ftp_cache[uid] = FTP_Features();
    ftp_cache[uid]$ret_code = code;
    }

# =============================================================================
# HTTP events
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
    if ( ! is_orig ) return;
    if ( name != "USER-AGENT" ) return;
    local uid = c$uid;
    if ( uid !in http_cache )
        http_cache[uid] = HTTP_Features();
    http_cache[uid]$user_agent = value;
    }

# =============================================================================
# Connection teardown — finalise features and write the log record
# =============================================================================

event connection_state_remove(c: connection) &priority=-5
    {
    local uid = c$uid;
    if ( uid !in pkt_count_fwd ) return;

    # ── Flow identity ────────────────────────────────────────────────────────
    local src_addr = c$id$orig_h;
    local src_port = port_to_count(c$id$orig_p);
    local dst_addr = c$id$resp_h;
    local dst_port = port_to_count(c$id$resp_p);
    local proto_num = proto_to_num(get_port_transport_proto(c$id$resp_p));

    # ── Duration (milliseconds) ──────────────────────────────────────────────
    local dur_sec: double = 0.0;
    if ( c?$duration )
        dur_sec = interval_to_double(c$duration);
    local dur_ms = dur_sec * 1000.0;

    # ── Byte counts (IP-level, from Zeek connection accounting) ─────────────
    local in_bytes:  count = 0;
    local out_bytes: count = 0;
    if ( c?$conn )
        {
        if ( c$conn?$orig_ip_bytes ) in_bytes  = c$conn$orig_ip_bytes;
        if ( c$conn?$resp_ip_bytes ) out_bytes = c$conn$resp_ip_bytes;
        }

    # ── Per-direction throughput ─────────────────────────────────────────────
    # SECOND_BYTES  = payload bytes per second
    # AVG_THROUGHPUT = IP-level bytes per second (matches nProbe semantics)
    local s2d_sec_bytes: double = 0.0;
    local d2s_sec_bytes: double = 0.0;
    local s2d_avg_tput:  double = 0.0;
    local d2s_avg_tput:  double = 0.0;
    if ( dur_sec > 0.0 )
        {
        s2d_sec_bytes = payload_bytes_fwd[uid] / dur_sec;
        d2s_sec_bytes = payload_bytes_bwd[uid] / dur_sec;
        s2d_avg_tput  = in_bytes  / dur_sec;
        d2s_avg_tput  = out_bytes / dur_sec;
        }

    # ── TTL sentinel handling (no IP packets seen → report 0/0, not 255/0) ──
    local min_ttl_val: count = 0;
    local max_ttl_val: count = 0;
    if ( ttl_max[uid] > 0 )
        {
        min_ttl_val = ttl_min[uid];
        max_ttl_val = ttl_max[uid];
        }

    # ── IP packet length sentinel handling ───────────────────────────────────
    local min_ip_len: count = 0;
    if ( ip_pkt_len_min[uid] < 65535 )
        min_ip_len = ip_pkt_len_min[uid];

    # ── IAT statistics per direction ─────────────────────────────────────────
    local fwd_iat = iat_stats(iat_fwd[uid]);   # [min, max, avg, stddev]
    local bwd_iat = iat_stats(iat_bwd[uid]);

    # ── Flow timestamps (milliseconds since epoch) ───────────────────────────
    local start_ms = time_to_double(flow_start_time[uid]) * 1000.0;
    local end_ms   = start_ms + dur_ms;

    # ── L7 protocol (Zeek service string) ────────────────────────────────────
    local l7: string = "";
    if ( c?$conn && c$conn?$service && c$conn$service != "" )
        l7 = c$conn$service;

    # ── Application-layer features ───────────────────────────────────────────
    local dns_qid:   count = 0;
    local dns_qtype: count = 0;
    local dns_ttl:   count = 0;
    local dns_rcode: count = 0;
    if ( uid in dns_cache )
        {
        dns_qid   = dns_cache[uid]$query_id;
        dns_qtype = dns_cache[uid]$query_type;
        dns_ttl   = dns_cache[uid]$ttl_answer;
        dns_rcode = dns_cache[uid]$response_code;
        }

    local ftp_code: count = 0;
    if ( uid in ftp_cache )
        ftp_code = ftp_cache[uid]$ret_code;

    local http_method: string = "";
    local http_url:    string = "";
    local http_ua:     string = "";
    if ( uid in http_cache )
        {
        http_method = http_cache[uid]$method;
        http_url    = http_cache[uid]$url;
        http_ua     = http_cache[uid]$user_agent;
        }

    local icmp_type:   count = 0;
    local icmp_v4type: count = 0;
    if ( uid in icmp_cache )
        {
        icmp_type   = icmp_cache[uid]$icmp_type;
        icmp_v4type = icmp_cache[uid]$icmp_ipv4_type;
        }
    # Fallback: Zeek encodes ICMP type in id.orig_p for ICMP flows
    else if ( get_port_transport_proto(c$id$resp_p) == icmp )
        icmp_type = port_to_count(c$id$orig_p);

    # ── Build and write the 53-field NF-v3 record ────────────────────────────
    local rec = Features(
        $IPV4_SRC_ADDR               = src_addr,
        $L4_SRC_PORT                 = src_port,
        $IPV4_DST_ADDR               = dst_addr,
        $L4_DST_PORT                 = dst_port,
        $PROTOCOL                    = proto_num,

        $IN_BYTES                    = in_bytes,
        $OUT_BYTES                   = out_bytes,
        $IN_PKTS                     = pkt_count_fwd[uid],
        $OUT_PKTS                    = pkt_count_bwd[uid],

        $FLOW_DURATION_MILLISECONDS  = dur_ms,

        $MIN_IP_PKT_LEN              = min_ip_len,
        $MAX_IP_PKT_LEN              = ip_pkt_len_max[uid],

        $SRC_TO_DST_SECOND_BYTES     = s2d_sec_bytes,
        $DST_TO_SRC_SECOND_BYTES     = d2s_sec_bytes,
        $SRC_TO_DST_AVG_THROUGHPUT   = s2d_avg_tput,
        $DST_TO_SRC_AVG_THROUGHPUT   = d2s_avg_tput,

        $RETRANSMITTED_IN_BYTES      = retrans_in_bytes[uid],
        $RETRANSMITTED_IN_PKTS       = retrans_in_pkts[uid],
        $RETRANSMITTED_OUT_BYTES     = retrans_out_bytes[uid],
        $RETRANSMITTED_OUT_PKTS      = retrans_out_pkts[uid],

        $NUM_PKTS_UP_TO_128_BYTES    = hist_up_to_128[uid],
        $NUM_PKTS_128_TO_256_BYTES   = hist_128_256[uid],
        $NUM_PKTS_256_TO_512_BYTES   = hist_256_512[uid],
        $NUM_PKTS_512_TO_1024_BYTES  = hist_512_1024[uid],
        $NUM_PKTS_1024_TO_1514_BYTES = hist_1024_1514[uid],

        $TCP_WIN_MAX_IN              = tcp_win_max_in[uid],
        $TCP_WIN_MAX_OUT             = tcp_win_max_out[uid],

        $CLIENT_TCP_FLAGS            = tcp_flags_client[uid],
        $SERVER_TCP_FLAGS            = tcp_flags_server[uid],
        $TCP_FLAGS                   = tcp_flags_client[uid] | tcp_flags_server[uid],

        $MIN_TTL                     = min_ttl_val,
        $MAX_TTL                     = max_ttl_val,

        $ICMP_TYPE                   = icmp_type,
        $ICMP_IPV4_TYPE              = icmp_v4type,

        $DNS_QUERY_ID                = dns_qid,
        $DNS_QUERY_TYPE              = dns_qtype,
        $DNS_TTL_ANSWER              = dns_ttl,
        $DNS_RESPONSE_CODE           = dns_rcode,

        $FTP_COMMAND_RET_CODE        = ftp_code,

        $L7_PROTO                    = l7,

        $HTTP_URL                    = http_url,
        $HTTP_METHOD                 = http_method,
        $HTTP_USER_AGENT             = http_ua,

        $FLOW_START_MILLISECONDS     = start_ms,
        $FLOW_END_MILLISECONDS       = end_ms,

        $SRC_TO_DST_IAT_MIN          = fwd_iat[0],
        $SRC_TO_DST_IAT_MAX          = fwd_iat[1],
        $SRC_TO_DST_IAT_AVG          = fwd_iat[2],
        $SRC_TO_DST_IAT_STDDEV       = fwd_iat[3],
        $DST_TO_SRC_IAT_MIN          = bwd_iat[0],
        $DST_TO_SRC_IAT_MAX          = bwd_iat[1],
        $DST_TO_SRC_IAT_AVG          = bwd_iat[2],
        $DST_TO_SRC_IAT_STDDEV       = bwd_iat[3]
    );

    Log::write(FlowMeter::LOG, rec);
    cleanup_flow(uid);
    }
