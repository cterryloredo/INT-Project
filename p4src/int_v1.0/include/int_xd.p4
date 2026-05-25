/*
 * INT-XD (Export Data) support
 *
 * Each switch independently clones packets that match the XD watchlist
 * and exports a telemetry report directly to the collector.
 * The original packet is never modified.
 *
 * Two controls:
 *   Int_xd_config  - runs in INGRESS: checks watchlist, triggers I2E clone
 *   Int_xd_report  - runs in EGRESS:  detects the clone, builds the report
 */

#ifdef BMV2

// Mirror session ID for INT-XD clones.
// Must be different from INT_REPORT_MIRROR_SESSION_ID (which is 1, used by INT-MD sink).
const bit<32> INT_XD_MIRROR_SESSION_ID = 2;

// ─── Ingress control ────────────────────────────────────────────────────────

control Int_xd_config(inout headers hdr,
                      inout metadata meta,
                      inout standard_metadata_t standard_metadata) {

    // Mark the metadata so egress knows this clone is XD (not MD-sink).
    action set_xd_clone() {
        meta.int_metadata.xd_clone = 1;
        clone3<metadata>(CloneType.I2E, INT_XD_MIRROR_SESSION_ID, meta);
    }

    // XD watchlist: operator configures which flows to export.
    // Matches on src IP, dst IP, L4 src port, L4 dst port (all ternary).
    table tb_int_xd_watchlist {
        actions = {
            set_xd_clone;
        }
        key = {
            hdr.ipv4.srcAddr              : ternary;
            hdr.ipv4.dstAddr              : ternary;
            meta.layer34_metadata.l4_src  : ternary;
            meta.layer34_metadata.l4_dst  : ternary;
        }
        size = 127;
    }

    apply {
        // Only try to match if this is a normal (non-clone) packet
        // and it carries IPv4.
        if (hdr.ipv4.isValid() &&
            standard_metadata.instance_type == PKT_INSTANCE_TYPE_NORMAL) {
            tb_int_xd_watchlist.apply();
        }
    }
}

// ─── Egress control ─────────────────────────────────────────────────────────

control Int_xd_report(inout headers hdr,
                      inout metadata meta,
                      inout standard_metadata_t standard_metadata) {

    // Sequence number register for XD reports (independent from MD register).
    register<bit<32>>(1) xd_seq_num_register;

    // Build the INT-XD telemetry report.
    // The report format reuses the existing report header structure so the
    // same Python collector can parse both MD and XD reports.
    // The only difference visible to the collector is the absence of an
    // INT shim / INT data stack — it will be tagged by the collector itself
    // based on which UDP port / which report format it sees.
    action send_xd_report(bit<48> dp_mac,
                          bit<32> dp_ip,
                          bit<48> collector_mac,
                          bit<32> collector_ip,
                          bit<16> collector_port,
                          bit<32> switch_id) {

        bit<32> seq_val = 0;

        // ── Outer Ethernet ───────────────────────────────────────────────
        hdr.report_ethernet.setValid();
        hdr.report_ethernet.dstAddr  = collector_mac;
        hdr.report_ethernet.srcAddr  = dp_mac;
        hdr.report_ethernet.etherType = 0x0800;

        // ── Outer IPv4 ───────────────────────────────────────────────────
        hdr.report_ipv4.setValid();
        hdr.report_ipv4.version    = 4;
        hdr.report_ipv4.ihl        = 5;
        hdr.report_ipv4.dscp       = 0;
        hdr.report_ipv4.ecn        = 0;
        // Fixed sizes: outer eth(14) + outer ip(20) + outer udp(8)
        //            + report_fixed_header(16)
        //            + inner eth(14) + inner ip(20) + inner udp/tcp(8)
        //            + XD metadata (switch_id:4 + port_ids:4 +
        //                           hop_latency:4 + q_occupancy:4 +
        //                           ingress_tstamp:8 + egress_tstamp:8) = 32
        // Total inner payload = 14+20+8+32 = 74
        // report_ipv4.totalLen = 20+8+16+74 = 118
        hdr.report_ipv4.totalLen   = 118;
        hdr.report_ipv4.id         = 0;
        hdr.report_ipv4.flags      = 0;
        hdr.report_ipv4.fragOffset = 0;
        hdr.report_ipv4.ttl        = 64;
        hdr.report_ipv4.protocol   = 17; // UDP
        hdr.report_ipv4.srcAddr    = dp_ip;
        hdr.report_ipv4.dstAddr    = collector_ip;

        // ── Outer UDP ────────────────────────────────────────────────────
        hdr.report_udp.setValid();
        hdr.report_udp.srcPort = 0;
        hdr.report_udp.dstPort = collector_port;
        hdr.report_udp.len     = 98;  // totalLen - 20
        hdr.report_udp.csum    = 0;

        // ── INT Report Fixed Header ──────────────────────────────────────
        hdr.report_fixed_header.setValid();
        hdr.report_fixed_header.ver              = INT_REPORT_VERSION;
        hdr.report_fixed_header.len              = INT_REPORT_HEADER_LEN_WORDS;
        hdr.report_fixed_header.nprot            = 0;
        hdr.report_fixed_header.rep_md_bits_high = 0;
        hdr.report_fixed_header.rep_md_bits_low  = 0;
        hdr.report_fixed_header.reserved         = 0;
        hdr.report_fixed_header.d                = 0;
        hdr.report_fixed_header.q                = 0;
        hdr.report_fixed_header.f                = 1;
        hdr.report_fixed_header.hw_id            = 0;
        hdr.report_fixed_header.switch_id        = switch_id;

        xd_seq_num_register.read(seq_val, 0);
        hdr.report_fixed_header.seq_num          = seq_val;
        xd_seq_num_register.write(0, seq_val + 1);

        hdr.report_fixed_header.ingress_tstamp =
            (bit<32>)meta.int_metadata.ingress_tstamp;

        // ── XD metadata fields (reuse existing INT metadata headers) ─────
        // These are the per-hop fields the collector will read.
        hdr.int_switch_id.setValid();
        hdr.int_switch_id.switch_id = switch_id;

        hdr.int_port_ids.setValid();
        hdr.int_port_ids.ingress_port_id = meta.int_metadata.ingress_port;
        hdr.int_port_ids.egress_port_id  =
            (bit<16>)standard_metadata.egress_port;

        hdr.int_hop_latency.setValid();
        hdr.int_hop_latency.hop_latency =
            (bit<32>)(standard_metadata.egress_global_timestamp -
                      standard_metadata.ingress_global_timestamp);

        hdr.int_q_occupancy.setValid();
        hdr.int_q_occupancy.q_id         = 0;
        hdr.int_q_occupancy.q_occupancy  =
            (bit<24>)standard_metadata.enq_qdepth;

        hdr.int_ingress_tstamp.setValid();
        bit<64> _its = (bit<64>)meta.int_metadata.ingress_tstamp;
        hdr.int_ingress_tstamp.ingress_tstamp = 1000 * _its;

        hdr.int_egress_tstamp.setValid();
        bit<64> _ets = (bit<64>)standard_metadata.egress_global_timestamp;
        hdr.int_egress_tstamp.egress_tstamp = 1000 * _ets;

        // Truncate to the exact report size so no payload leaks out.
        // 14 (outer eth) + 118 (report_ipv4.totalLen) = 132 bytes
        truncate((bit<32>)132);
    }

    // One entry per switch — same parameters as tb_int_reporting in int_report.p4
    table tb_int_xd_reporting {
        actions = {
            send_xd_report;
        }
        size = 512;
    }

    apply {
        // Distinguish XD clones from MD clones by the absence of INT headers.
        // MD clones always have int_shim valid (added by Int_source).
        // XD clones never modify the packet so int_shim is never valid.
        if (standard_metadata.instance_type == PKT_INSTANCE_TYPE_INGRESS_CLONE
            && !hdr.int_shim.isValid()) {
            tb_int_xd_reporting.apply();
        }
    }
}

#endif  // BMV2
