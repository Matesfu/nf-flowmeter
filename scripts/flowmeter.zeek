##! =============================================================================
##! flowmeter.zeek  —  NF-CSE-CIC-IDS2018-v3 Feature Extractor
##! =============================================================================
##!
##! Extracts the exact 53 features of the NF-CSE-CIC-IDS2018-v3 dataset family
##! as defined in Sarhan et al. (2022).
##!
##! Reference:
##!   M. Sarhan, S. Layeghy, N. Moustafa, M. Portmann.
##!   "NetFlow Datasets for Machine Learning-Based Network Intrusion Detection
##!   Systems", Big Data Technologies and Applications, 2022.
##!
##! Usage (PCAP mode — works on WSL2):
##!   zeek -C -r traffic.pcap flowmeter
##!
##! Output:
##!   flowmeter.log  — one row per flow, 53 NF-v3 columns
##!
##! Zeek version: 8.x
##! Known API constraints respected:
##!   - new_packet(c, p)              — no len parameter in Zeek 8.x
##!   - icmp_info                     — icmp_conn does not exist
##!   - context$proto                 — icmp_context has no $ip or $ip_hdr
##!   - port_to_count()               — count_of() does not exist
##!   - double_to_count(interval_to_double(ans$TTL)) — TTL is interval not count
##!   - c$conn$proto == "icmp"        — proto is string, not identifier
##!   - distinct loop variable names  — no duplicate local declarations
##! =============================================================================

module FlowMeter;

export {

    redef enum Log::ID += { LOG };

    # ── Helper statistics record ───────────────────────────────────────────────
    type statistics_info: record {
        min: double &default=0.0;
        max: double &default=0.0;
        avg: double &default=0.0;
        std: double &default=0.0;
    };

    # ── Application-layer feature cache records ────────────────────────────────
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

    # ── NF-CSE-CIC-IDS2018-v3 log record — exactly 53 fields ──────────────────
    type Features: record {

        # 1–5: Flow identity
        IPV4_SRC_ADDR:              string  &log &default="";
        L4_SRC_PORT:                count   &log &default=0;
        IPV4_DST_ADDR:              string  &log &default="";
        L4_DST_PORT:                count   &log &default=0;
        PROTOCOL:                   count   &log &default=0;

        # 6: L7 protocol (nDPI-compatible numeric ID, best-effort from service)
        L7_PROTO:                   double  &log &default=0.0;

        # 7–10: Byte and packet counts (IP-level)
        IN_BYTES:                   count   &log &default=0;
        IN_PKTS:                    count   &log &default=0;
        OUT_BYTES:                  count   &log &default=0;
        OUT_PKTS:                   count   &log &default=0;

        # 11–13: TCP flags
        TCP_FLAGS:                  count   &log &default=0;
        CLIENT_TCP_FLAGS:           count   &log &default=0;
        SERVER_TCP_FLAGS:           count   &log &default=0;

        # 14–16: Flow timing
        FLOW_DURATION_MILLISECONDS: double  &log &default=0.0;
        FLOW_START_MILLISECONDS:    double  &log &default=0.0;
        FLOW_END_MILLISECONDS:      double  &log &default=0.0;

        # 17–24: Inter-arrival times (microseconds)
        SRC_TO_DST_IAT_MIN:         double  &log &default=0.0;
        SRC_TO_DST_IAT_MAX:         double  &log &default=0.0;
        SRC_TO_DST_IAT_AVG:         double  &log &default=0.0;
        SRC_TO_DST_IAT_STDDEV:      double  &log &default=0.0;
        DST_TO_SRC_IAT_MIN:         double  &log &default=0.0;
        DST_TO_SRC_IAT_MAX:         double  &log &default=0.0;
        DST_TO_SRC_IAT_AVG:         double  &log &default=0.0;
        DST_TO_SRC_IAT_STDDEV:      double  &log &default=0.0;

        # 25–28: TCP retransmissions
        RETRANSMITTED_IN_BYTES:     count   &log &default=0;
        RETRANSMITTED_IN_PKTS:      count   &log &default=0;
        RETRANSMITTED_OUT_BYTES:    count   &log &default=0;
        RETRANSMITTED_OUT_PKTS:     count   &log &default=0;

        # 29–32: Per-direction throughput (IP-level bytes/sec)
        SRC_TO_DST_SECOND_BYTES:    double  &log &default=0.0;
        DST_TO_SRC_SECOND_BYTES:    double  &log &default=0.0;
        SRC_TO_DST_AVG_THROUGHPUT:  double  &log &default=0.0;
        DST_TO_SRC_AVG_THROUGHPUT:  double  &log &default=0.0;

        # 33–37: Packet size histogram bins (full IP packet length)
        NUM_PKTS_UP_TO_128_BYTES:       count &log &default=0;
        NUM_PKTS_128_TO_256_BYTES:      count &log &default=0;
        NUM_PKTS_256_TO_512_BYTES:      count &log &default=0;
        NUM_PKTS_512_TO_1024_BYTES:     count &log &default=0;
        NUM_PKTS_1024_TO_1514_BYTES:    count &log &default=0;

        # 38–39: TCP window max per direction
        TCP_WIN_MAX_IN:             count   &log &default=0;
        TCP_WIN_MAX_OUT:            count   &log &default=0;

        # 40–41: ICMP
        ICMP_TYPE:                  count   &log &default=0;
        ICMP_IPV4_TYPE:             count   &log &default=0;

        # 42–45: DNS
        DNS_QUERY_ID:               count   &log &default=0;
        DNS_QUERY_TYPE:             count   &log &default=0;
        DNS_TTL_ANSWER:             count   &log &default=0;
        DNS_RESPONSE_CODE:          count   &log &default=0;

        # 46: FTP
        FTP_COMMAND_RET_CODE:       count   &log &default=0;

        # 47–49: HTTP
        HTTP_URL:                   string  &log &default="";
        HTTP_METHOD:                string  &log &default="";
        HTTP_USER_AGENT:            string  &log &default="";

        # 50–51: IP packet length extremes
        MIN_IP_PKT_LEN:             count   &log &default=0;
        MAX_IP_PKT_LEN:             count   &log &default=0;

        # 52–53: TTL extremes
        MIN_TTL:                    count   &log &default=0;
        MAX_TTL:                    count   &log &default=0;
    };
}

# =============================================================================
# nDPI-compatible L7 protocol numeric ID mapping
# Maps Zeek DPD service strings to nDPI protocol numbers.
# Reference: https://github.com/ntop/nDPI/blob/dev/src/include/ndpi_protocol_ids.h
# This is best-effort — Zeek service strings do not map 1:1 to nDPI IDs.
# =============================================================================
global ndpi_proto_map: table[string] of count = {
    ["ftp"]         = 1,
    ["ftp-data"]    = 2,
    ["smtp"]        = 3,
    ["pop3"]        = 4,
    ["imap"]        = 10,
    ["dns"]         = 5,
    ["http"]        = 7,
    ["mdns"]        = 8,
    ["ntp"]         = 102,
    ["snmp"]        = 57,
    ["bgp"]         = 67,
    ["irc"]         = 35,
    ["ldap"]        = 61,
    ["telnet"]      = 23,
    ["ssh"]         = 92,
    ["ssl"]         = 91,
    ["rdp"]         = 102,
    ["sip"]         = 57,
    ["dhcp"]        = 18,
    ["tftp"]        = 16,
    ["mysql"]       = 96,
    ["postgresql"]  = 97,
    ["krb"]         = 64,
    ["kerberos"]    = 64,
    ["netbios"]     = 33,
    ["smb"]         = 33,
    ["icmp"]        = 81,
    ["icmpv6"]      = 82
};

# Transport protocol string → IANA protocol number
global proto_num_map: table[string] of count = {
    ["tcp"]     = 6,
    ["udp"]     = 17,
    ["icmp"]    = 1,
    ["icmp6"]   = 58,
    ["icmpv6"]  = 58,
    ["sctp"]    = 132,
    ["gre"]     = 47,
    ["esp"]     = 50,
    ["ah"]      = 51
};

# =============================================================================
# Internal per-flow state tables (keyed by uid string)
# =============================================================================

# Packet counts per direction
global pkt_count_fwd:   table[string] of count;
global pkt_count_bwd:   table[string] of count;

# IAT tracking
global last_pkt_time_fwd:  table[string] of time;
global last_pkt_time_bwd:  table[string] of time;
global iat_fwd:            table[string] of vector of double;
global iat_bwd:            table[string] of vector of double;

# TCP flag bitmasks
global tcp_flags_client:   table[string] of count;
global tcp_flags_server:   table[string] of count;

# TCP window max per direction
global tcp_win_max_in:     table[string] of count;
global tcp_win_max_out:    table[string] of count;

# IP packet length extremes
global ip_pkt_len_min:     table[string] of count;
global ip_pkt_len_max:     table[string] of count;

# TTL extremes
global ttl_min:            table[string] of count;
global ttl_max:            table[string] of count;

# Packet size histogram bins
global hist_up_to_128:     table[string] of count;
global hist_128_256:       table[string] of count;
global hist_256_512:       table[string] of count;
global hist_512_1024:      table[string] of count;
global hist_1024_1514:     table[string] of count;

# TCP retransmission counters
global retrans_in_pkts:    table[string] of count;
global retrans_in_bytes:   table[string] of count;
global retrans_out_pkts:   table[string] of count;
global retrans_out_bytes:  table[string] of count;

# Flow start time
global flow_start_time:    table[string] of time;

# Application-layer feature caches
global dns_cache:          table[string] of DNS_Features;
global http_cache:         table[string] of HTTP_Features;
global ftp_cache:          table[string] of FTP_Features;
global icmp_cache:         table[string] of ICMP_Features;

# =============================================================================
# Helper: compute IAT statistics from a vector of doubles
# =============================================================================

function iat_stats(vec: vector of double): statistics_info
    {
    local s = statistics_info();
    if ( |vec| == 0 ) return s;

    local n    = |vec|;
    local mn   = vec[0];
    local mx   = vec[0];
    local sum  = 0.0;

    for ( vi in vec )
        {
        local vv = vec[vi];
        sum += vv;
        if ( vv < mn ) mn = vv;
        if ( vv > mx ) mx = vv;
        }

    local avg = sum / n;
    local variance = 0.0;

    for ( vj in vec )
        {
        local d = vec[vj] - avg;
        variance += d * d;
        }

    s$min = mn;
    s$max = mx;
    s$avg = avg;
    s$std = sqrt(variance / n);
    return s;
    }

# =============================================================================
# Flow initialisation
# =============================================================================

function init_flow(uid: string, ts: time)
    {
    pkt_count_fwd[uid]    = 0;
    pkt_count_bwd[uid]    = 0;
    iat_fwd[uid]          = vector();
    iat_bwd[uid]          = vector();
    tcp_flags_client[uid] = 0;
    tcp_flags_server[uid] = 0;
    tcp_win_max_in[uid]   = 0;
    tcp_win_max_out[uid]  = 0;
    ip_pkt_len_min[uid]   = 65535;
    ip_pkt_len_max[uid]   = 0;
    ttl_min[uid]          = 255;
    ttl_max[uid]          = 0;
    hist_up_to_128[uid]   = 0;
    hist_128_256[uid]     = 0;
    hist_256_512[uid]     = 0;
    hist_512_1024[uid]    = 0;
    hist_1024_1514[uid]   = 0;
    retrans_in_pkts[uid]  = 0;
    retrans_in_bytes[uid] = 0;
    retrans_out_pkts[uid] = 0;
    retrans_out_bytes[uid]= 0;
    flow_start_time[uid]  = ts;
    }

# =============================================================================
# Flow cleanup
# =============================================================================

function cleanup_flow(uid: string)
    {
    delete pkt_count_fwd[uid];
    delete pkt_count_bwd[uid];
    if ( uid in last_pkt_time_fwd ) delete last_pkt_time_fwd[uid];
    if ( uid in last_pkt_time_bwd ) delete last_pkt_time_bwd[uid];
    delete iat_fwd[uid];
    delete iat_bwd[uid];
    delete tcp_flags_client[uid];
    delete tcp_flags_server[uid];
    delete tcp_win_max_in[uid];
    delete tcp_win_max_out[uid];
    delete ip_pkt_len_min[uid];
    delete ip_pkt_len_max[uid];
    delete ttl_min[uid];
    delete ttl_max[uid];
    delete hist_up_to_128[uid];
    delete hist_128_256[uid];
    delete hist_256_512[uid];
    delete hist_512_1024[uid];
    delete hist_1024_1514[uid];
    delete retrans_in_pkts[uid];
    delete retrans_in_bytes[uid];
    delete retrans_out_pkts[uid];
    delete retrans_out_bytes[uid];
    delete flow_start_time[uid];
    if ( uid in dns_cache )  delete dns_cache[uid];
    if ( uid in http_cache ) delete http_cache[uid];
    if ( uid in ftp_cache )  delete ftp_cache[uid];
    if ( uid in icmp_cache ) delete icmp_cache[uid];
    }

# =============================================================================
# Log stream initialisation
# =============================================================================

event zeek_init()
    {
    Log::create_stream(FlowMeter::LOG,
        [$columns=Features, $path="flowmeter"]);
    }

# =============================================================================
# Connection init
# =============================================================================

event new_connection(c: connection)
    {
    init_flow(c$uid, c$start_time);
    }

# =============================================================================
# Per-packet processing
# FIX: Zeek 8.x new_packet signature is (c: connection, p: pkt_hdr)
#      — no third len: count parameter.
# =============================================================================

event new_packet(c: connection, p: pkt_hdr) &priority=5
    {
    local uid = c$uid;
    if ( uid !in pkt_count_fwd ) return;

    local ts = network_time();

    # ── Direction ──────────────────────────────────────────────────────────────
    local is_orig = F;
    if ( p?$ip )
        is_orig = ( p$ip$src == c$id$orig_h );
    else if ( p?$ip6 )
        is_orig = ( p$ip6$src == c$id$orig_h );

    # ── Full IP packet length and TTL ──────────────────────────────────────────
    local full_len: count = 0;
    local ttl_val:  count = 0;

    if ( p?$ip )
        {
        full_len = p$ip$len;
        ttl_val  = p$ip$ttl;
        }
    else if ( p?$ip6 )
        {
        full_len = p$ip6$len + 40;   # payload length + 40-byte fixed IPv6 header
        ttl_val  = p$ip6$hlim;
        }

    # ── TTL min/max ────────────────────────────────────────────────────────────
    if ( ttl_val > 0 )
        {
        if ( ttl_val < ttl_min[uid] ) ttl_min[uid] = ttl_val;
        if ( ttl_val > ttl_max[uid] ) ttl_max[uid] = ttl_val;
        }

    # ── IP packet length min/max ───────────────────────────────────────────────
    if ( full_len > 0 )
        {
        if ( full_len < ip_pkt_len_min[uid] ) ip_pkt_len_min[uid] = full_len;
        if ( full_len > ip_pkt_len_max[uid] ) ip_pkt_len_max[uid] = full_len;
        }

    # ── Packet size histogram bins ─────────────────────────────────────────────
    if      ( full_len <= 128  ) hist_up_to_128[uid]  += 1;
    else if ( full_len <= 256  ) hist_128_256[uid]    += 1;
    else if ( full_len <= 512  ) hist_256_512[uid]    += 1;
    else if ( full_len <= 1024 ) hist_512_1024[uid]   += 1;
    else                         hist_1024_1514[uid]  += 1;

    # ── TCP per-packet features ────────────────────────────────────────────────
    if ( p?$tcp )
        {
        local flags = p$tcp$flags;
        local win   = p$tcp$win;

        if ( is_orig )
            {
            tcp_flags_client[uid] = tcp_flags_client[uid] | flags;
            if ( win > tcp_win_max_in[uid] ) tcp_win_max_in[uid] = win;
            }
        else
            {
            tcp_flags_server[uid] = tcp_flags_server[uid] | flags;
            if ( win > tcp_win_max_out[uid] ) tcp_win_max_out[uid] = win;
            }
        }

    # ── Packet counts ──────────────────────────────────────────────────────────
    if ( is_orig )
        pkt_count_fwd[uid] += 1;
    else
        pkt_count_bwd[uid] += 1;

    # ── IAT ───────────────────────────────────────────────────────────────────
    if ( is_orig )
        {
        if ( uid in last_pkt_time_fwd )
            {
            local iat_f = interval_to_double(ts - last_pkt_time_fwd[uid]) * 1e6;
            iat_fwd[uid] += vector(iat_f);
            }
        last_pkt_time_fwd[uid] = ts;
        }
    else
        {
        if ( uid in last_pkt_time_bwd )
            {
            local iat_b = interval_to_double(ts - last_pkt_time_bwd[uid]) * 1e6;
            iat_bwd[uid] += vector(iat_b);
            }
        last_pkt_time_bwd[uid] = ts;
        }
    }

# =============================================================================
# TCP retransmission
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
# FIX: second parameter is icmp_info — icmp_conn does not exist in Zeek.
# FIX: icmp_context has no $ip or $ip_hdr field — use context$proto.
# =============================================================================

event icmp_sent(c: connection, icmp: icmp_info)
    {
    local uid = c$uid;
    if ( uid !in pkt_count_fwd ) return;
    if ( uid !in icmp_cache ) icmp_cache[uid] = ICMP_Features();
    icmp_cache[uid]$icmp_type = icmp$itype;
    }

event icmp_unreachable(c: connection, icmp: icmp_info,
                        code: count, context: icmp_context)
    {
    local uid = c$uid;
    if ( uid !in pkt_count_fwd ) return;
    if ( uid !in icmp_cache ) icmp_cache[uid] = ICMP_Features();
    icmp_cache[uid]$icmp_type = 3;  # Destination Unreachable
    # FIX: context$proto is the inner packet protocol — no $ip or $ip_hdr field
    if ( context$proto > 0 )
        icmp_cache[uid]$icmp_ipv4_type = context$proto;
    }

event icmp_time_exceeded(c: connection, icmp: icmp_info,
                          code: count, context: icmp_context)
    {
    local uid = c$uid;
    if ( uid !in pkt_count_fwd ) return;
    if ( uid !in icmp_cache ) icmp_cache[uid] = ICMP_Features();
    icmp_cache[uid]$icmp_type = 11;  # Time Exceeded
    # FIX: context$proto is the inner packet protocol
    if ( context$proto > 0 )
        icmp_cache[uid]$icmp_ipv4_type = context$proto;
    }

event icmp_echo_request(c: connection, icmp: icmp_info,
                         id: count, seq: count, payload: string)
    {
    local uid = c$uid;
    if ( uid !in pkt_count_fwd ) return;
    if ( uid !in icmp_cache ) icmp_cache[uid] = ICMP_Features();
    icmp_cache[uid]$icmp_type = 8;  # Echo Request
    }

event icmp_echo_reply(c: connection, icmp: icmp_info,
                       id: count, seq: count, payload: string)
    {
    local uid = c$uid;
    if ( uid !in pkt_count_fwd ) return;
    if ( uid !in icmp_cache ) icmp_cache[uid] = ICMP_Features();
    icmp_cache[uid]$icmp_type = 0;  # Echo Reply
    }

# =============================================================================
# DNS events
# FIX: ans$TTL is type interval — cast with double_to_count(interval_to_double())
# =============================================================================

event dns_request(c: connection, msg: dns_msg, query: string,
                  qtype: count, qclass: count)
    {
    local uid = c$uid;
    if ( uid !in pkt_count_fwd ) return;
    if ( uid !in dns_cache ) dns_cache[uid] = DNS_Features();
    dns_cache[uid]$query_id   = msg$id;
    dns_cache[uid]$query_type = qtype;
    }

event dns_A_reply(c: connection, msg: dns_msg, ans: dns_answer, a: addr)
    {
    local uid = c$uid;
    if ( uid !in pkt_count_fwd ) return;
    if ( uid !in dns_cache ) dns_cache[uid] = DNS_Features();
    dns_cache[uid]$response_code = msg$rcode;
    dns_cache[uid]$ttl_answer    = double_to_count(interval_to_double(ans$TTL));
    }

event dns_AAAA_reply(c: connection, msg: dns_msg, ans: dns_answer, a: addr)
    {
    local uid = c$uid;
    if ( uid !in pkt_count_fwd ) return;
    if ( uid !in dns_cache ) dns_cache[uid] = DNS_Features();
    dns_cache[uid]$response_code = msg$rcode;
    dns_cache[uid]$ttl_answer    = double_to_count(interval_to_double(ans$TTL));
    }

event dns_MX_reply(c: connection, msg: dns_msg, ans: dns_answer,
                   name: string, preference: count)
    {
    local uid = c$uid;
    if ( uid !in pkt_count_fwd ) return;
    if ( uid !in dns_cache ) dns_cache[uid] = DNS_Features();
    dns_cache[uid]$response_code = msg$rcode;
    dns_cache[uid]$ttl_answer    = double_to_count(interval_to_double(ans$TTL));
    }

event dns_NS_reply(c: connection, msg: dns_msg, ans: dns_answer, name: string)
    {
    local uid = c$uid;
    if ( uid !in pkt_count_fwd ) return;
    if ( uid !in dns_cache ) dns_cache[uid] = DNS_Features();
    dns_cache[uid]$response_code = msg$rcode;
    dns_cache[uid]$ttl_answer    = double_to_count(interval_to_double(ans$TTL));
    }

event dns_CNAME_reply(c: connection, msg: dns_msg, ans: dns_answer, name: string)
    {
    local uid = c$uid;
    if ( uid !in pkt_count_fwd ) return;
    if ( uid !in dns_cache ) dns_cache[uid] = DNS_Features();
    dns_cache[uid]$response_code = msg$rcode;
    dns_cache[uid]$ttl_answer    = double_to_count(interval_to_double(ans$TTL));
    }

event dns_rejected(c: connection, msg: dns_msg, query: string,
                   qtype: count, qclass: count)
    {
    local uid = c$uid;
    if ( uid !in pkt_count_fwd ) return;
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
    if ( uid !in pkt_count_fwd ) return;
    if ( uid !in ftp_cache ) ftp_cache[uid] = FTP_Features();
    ftp_cache[uid]$ret_code = code;
    }

# =============================================================================
# HTTP events
# =============================================================================

event http_request(c: connection, method: string, original_URI: string,
                   unescaped_URI: string, version: string)
    {
    local uid = c$uid;
    if ( uid !in pkt_count_fwd ) return;
    if ( uid !in http_cache ) http_cache[uid] = HTTP_Features();
    http_cache[uid]$method = method;
    http_cache[uid]$url    = original_URI;
    }

event http_header(c: connection, is_orig: bool, name: string, value: string)
    {
    if ( !is_orig ) return;
    local uid = c$uid;
    if ( uid !in pkt_count_fwd ) return;
    if ( name == "USER-AGENT" )
        {
        if ( uid !in http_cache ) http_cache[uid] = HTTP_Features();
        http_cache[uid]$user_agent = value;
        }
    }

# =============================================================================
# Connection close — compute all final NF-v3 features and write log row
# =============================================================================

event connection_state_remove(c: connection) &priority=-5
    {
    local uid = c$uid;
    if ( uid !in pkt_count_fwd ) return;

    # ── Flow identity from conn record ─────────────────────────────────────────
    local src_addr = fmt("%s", c$id$orig_h);
    local dst_addr = fmt("%s", c$id$resp_h);
    local src_port = port_to_count(c$id$orig_p);
    local dst_port = port_to_count(c$id$resp_p);

    # ── Transport protocol number ──────────────────────────────────────────────
    local proto_num: count = 0;
    if ( c$conn?$proto )
        {
        local proto_str = c$conn$proto;
        if ( proto_str in proto_num_map )
            proto_num = proto_num_map[proto_str];
        }

    # ── L7 protocol (nDPI best-effort) ─────────────────────────────────────────
    local l7: double = 0.0;
    if ( c$conn?$service && c$conn$service != "" )
        {
        local svc = c$conn$service;
        if ( svc in ndpi_proto_map )
            l7 = ndpi_proto_map[svc] + 0.0;
        }

    # ── IP-level byte counts ───────────────────────────────────────────────────
    local in_bytes:  count = 0;
    local out_bytes: count = 0;
    if ( c?$conn )
        {
        if ( c$conn?$orig_ip_bytes ) in_bytes  = c$conn$orig_ip_bytes;
        if ( c$conn?$resp_ip_bytes ) out_bytes = c$conn$resp_ip_bytes;
        }

    # ── Packet counts ──────────────────────────────────────────────────────────
    local in_pkts  = pkt_count_fwd[uid];
    local out_pkts = pkt_count_bwd[uid];

    # ── Flow duration and timestamps ───────────────────────────────────────────
    local dur_sec: double = 0.0;
    if ( c?$duration )
        dur_sec = interval_to_double(c$duration);

    local flow_start_ms: double = 0.0;
    if ( uid in flow_start_time )
        flow_start_ms = time_to_double(flow_start_time[uid]) * 1000.0;

    local flow_dur_ms  = dur_sec * 1000.0;
    local flow_end_ms  = flow_start_ms + flow_dur_ms;

    # ── TCP flags ──────────────────────────────────────────────────────────────
    local cli_flags = tcp_flags_client[uid];
    local srv_flags = tcp_flags_server[uid];
    local all_flags = cli_flags | srv_flags;

    # ── IAT statistics ─────────────────────────────────────────────────────────
    local fwd_iat = iat_stats(iat_fwd[uid]);
    local bwd_iat = iat_stats(iat_bwd[uid]);

    # ── Throughput (IP-level bytes / duration) ─────────────────────────────────
    local src_dst_sec:  double = 0.0;
    local dst_src_sec:  double = 0.0;
    local src_dst_tput: double = 0.0;
    local dst_src_tput: double = 0.0;
    if ( dur_sec > 0.0 )
        {
        src_dst_sec  = in_bytes  / dur_sec;
        dst_src_sec  = out_bytes / dur_sec;
        src_dst_tput = in_bytes  / dur_sec;
        dst_src_tput = out_bytes / dur_sec;
        }

    # ── IP packet length (sanitise default 65535 → 0 if no packets seen) ───────
    local min_pkt = ( ip_pkt_len_min[uid] == 65535 ) ? 0 : ip_pkt_len_min[uid];
    local max_pkt = ip_pkt_len_max[uid];

    # ── TTL (sanitise default 255 → 0 if no IP packets seen) ──────────────────
    local min_ttl_val = ( ttl_min[uid] == 255 ) ? 0 : ttl_min[uid];
    local max_ttl_val = ttl_max[uid];

    # ── ICMP fields ────────────────────────────────────────────────────────────
    local icmp_t:  count = 0;
    local icmp_i4: count = 0;
    if ( uid in icmp_cache )
        {
        icmp_t  = icmp_cache[uid]$icmp_type;
        icmp_i4 = icmp_cache[uid]$icmp_ipv4_type;
        }
    # FIX: for ICMP flows with no explicit icmp_* event,
    #      Zeek encodes ICMP type in id.orig_p (type port).
    #      FIX: use port_to_count() — count_of() does not exist.
    #      FIX: c$conn$proto is string — compare with "icmp" not bare icmp.
    else if ( c$conn?$proto && c$conn$proto == "icmp" )
        icmp_t = port_to_count(c$id$orig_p);

    # ── DNS fields ─────────────────────────────────────────────────────────────
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

    # ── FTP fields ─────────────────────────────────────────────────────────────
    local ftp_code: count = 0;
    if ( uid in ftp_cache )
        ftp_code = ftp_cache[uid]$ret_code;

    # ── HTTP fields ────────────────────────────────────────────────────────────
    local http_url: string = "";
    local http_mth: string = "";
    local http_ua:  string = "";
    if ( uid in http_cache )
        {
        http_url = http_cache[uid]$url;
        http_mth = http_cache[uid]$method;
        http_ua  = http_cache[uid]$user_agent;
        }

    # ── Write log record ───────────────────────────────────────────────────────
    local rec = Features(
        $IPV4_SRC_ADDR              = src_addr,
        $L4_SRC_PORT                = src_port,
        $IPV4_DST_ADDR              = dst_addr,
        $L4_DST_PORT                = dst_port,
        $PROTOCOL                   = proto_num,
        $L7_PROTO                   = l7,
        $IN_BYTES                   = in_bytes,
        $IN_PKTS                    = in_pkts,
        $OUT_BYTES                  = out_bytes,
        $OUT_PKTS                   = out_pkts,
        $TCP_FLAGS                  = all_flags,
        $CLIENT_TCP_FLAGS           = cli_flags,
        $SERVER_TCP_FLAGS           = srv_flags,
        $FLOW_DURATION_MILLISECONDS = flow_dur_ms,
        $FLOW_START_MILLISECONDS    = flow_start_ms,
        $FLOW_END_MILLISECONDS      = flow_end_ms,
        $SRC_TO_DST_IAT_MIN         = fwd_iat$min,
        $SRC_TO_DST_IAT_MAX         = fwd_iat$max,
        $SRC_TO_DST_IAT_AVG         = fwd_iat$avg,
        $SRC_TO_DST_IAT_STDDEV      = fwd_iat$std,
        $DST_TO_SRC_IAT_MIN         = bwd_iat$min,
        $DST_TO_SRC_IAT_MAX         = bwd_iat$max,
        $DST_TO_SRC_IAT_AVG         = bwd_iat$avg,
        $DST_TO_SRC_IAT_STDDEV      = bwd_iat$std,
        $RETRANSMITTED_IN_BYTES     = retrans_in_bytes[uid],
        $RETRANSMITTED_IN_PKTS      = retrans_in_pkts[uid],
        $RETRANSMITTED_OUT_BYTES    = retrans_out_bytes[uid],
        $RETRANSMITTED_OUT_PKTS     = retrans_out_pkts[uid],
        $SRC_TO_DST_SECOND_BYTES    = src_dst_sec,
        $DST_TO_SRC_SECOND_BYTES    = dst_src_sec,
        $SRC_TO_DST_AVG_THROUGHPUT  = src_dst_tput,
        $DST_TO_SRC_AVG_THROUGHPUT  = dst_src_tput,
        $NUM_PKTS_UP_TO_128_BYTES   = hist_up_to_128[uid],
        $NUM_PKTS_128_TO_256_BYTES  = hist_128_256[uid],
        $NUM_PKTS_256_TO_512_BYTES  = hist_256_512[uid],
        $NUM_PKTS_512_TO_1024_BYTES = hist_512_1024[uid],
        $NUM_PKTS_1024_TO_1514_BYTES= hist_1024_1514[uid],
        $TCP_WIN_MAX_IN             = tcp_win_max_in[uid],
        $TCP_WIN_MAX_OUT            = tcp_win_max_out[uid],
        $ICMP_TYPE                  = icmp_t,
        $ICMP_IPV4_TYPE             = icmp_i4,
        $DNS_QUERY_ID               = dns_qid,
        $DNS_QUERY_TYPE             = dns_qtype,
        $DNS_TTL_ANSWER             = dns_ttl,
        $DNS_RESPONSE_CODE          = dns_rcode,
        $FTP_COMMAND_RET_CODE       = ftp_code,
        $HTTP_URL                   = http_url,
        $HTTP_METHOD                = http_mth,
        $HTTP_USER_AGENT            = http_ua,
        $MIN_IP_PKT_LEN             = min_pkt,
        $MAX_IP_PKT_LEN             = max_pkt,
        $MIN_TTL                    = min_ttl_val,
        $MAX_TTL                    = max_ttl_val
    );

    Log::write(FlowMeter::LOG, rec);
    cleanup_flow(uid);
    }
