/* int_xd_tofino.p4
 * ---------------------------------------------------------------------------
 * Self-contained single-file Tofino (TNA) INT-XD exporter. SDE 9.13.4.
 *
 * WHAT IT DOES
 *   - Forwards IPv4 by exact-match dest IP (ipv4_fwd).
 *   - For flows on the XD watchlist: clones the packet (I2E mirror) to a
 *     collector port and builds an INT-XD telemetry report. Original packet is
 *     unmodified and still forwarded.
 *   - Report wire layout matches the existing Python collector (IntXdReport),
 *     so the collector + InfluxDB + Grafana stack works unchanged on UDP 6001.
 *
 */

#include <core.p4>
#include <tna.p4>

const bit<16> ETHERTYPE_IPV4 = 0x0800;
const bit<8>  IP_PROTO_UDP   = 0x11;
const bit<8>  IP_PROTO_TCP   = 0x06;

const bit<4> INT_REPORT_HEADER_LEN_WORDS = 4;
const bit<4> INT_REPORT_VERSION          = 1;

const bit<8> MIRROR_TYPE_XD = 1;  

// ---------------------------------------------------------------------------
// Headers
// ---------------------------------------------------------------------------

header ethernet_h {
    bit<48> dst_addr;
    bit<48> src_addr;
    bit<16> ether_type;
}

header ipv4_h {
    bit<4>  version;
    bit<4>  ihl;
    bit<6>  dscp;
    bit<2>  ecn;
    bit<16> total_len;
    bit<16> identification;
    bit<3>  flags;
    bit<13> frag_offset;
    bit<8>  ttl;
    bit<8>  protocol;
    bit<16> hdr_checksum;
    bit<32> src_addr;
    bit<32> dst_addr;
}

header udp_h {
    bit<16> src_port;
    bit<16> dst_port;
    bit<16> len;
    bit<16> checksum;
}

header tcp_h {
    bit<16> src_port;
    bit<16> dst_port;
    bit<32> seq_num;
    bit<32> ack_num;
    bit<4>  data_offset;
    bit<3>  reserved;
    bit<9>  flags;
    bit<16> win_size;
    bit<16> checksum;
    bit<16> urg_ptr;
}

header int_report_fixed_header_h {
    bit<4>  ver;
    bit<4>  len;
    bit<3>  nprot;
    bit<5>  rep_md_bits_high;
    bit<1>  rep_md_bits_low;
    bit<6>  reserved;
    bit<1>  d;
    bit<1>  q;
    bit<1>  f;
    bit<6>  hw_id;
    bit<32> switch_id;
    bit<32> seq_num;
    bit<32> ingress_tstamp;
}

header int_switch_id_h      { bit<32> switch_id; }
header int_port_ids_h       { bit<16> ingress_port_id; bit<16> egress_port_id; }
header int_hop_latency_h    { bit<32> hop_latency; }
header int_q_occupancy_h    { bit<8> q_id; bit<24> q_occupancy; }
header int_ingress_tstamp_h { bit<64> ingress_tstamp; }
header int_egress_tstamp_h  { bit<64> egress_tstamp; }

// Carried with the clone to egress. mirror_type is the first byte and is the
// clone discriminator read by the egress parser lookahead.
header mirror_h {
    bit<8>  mirror_type;
    bit<48> ingress_tstamp;
    bit<16> ingress_port;
}

// Bridged to egress on the original packet path (mirror_type stays 0).
header bridge_md_h {
    bit<8>  mirror_type;
    bit<48> ingress_tstamp;
    bit<16> ingress_port;
}

struct headers_t {
    bridge_md_h               bridge_md;
    mirror_h                  mirror_md;
    ethernet_h                report_ethernet;
    ipv4_h                    report_ipv4;
    udp_h                     report_udp;
    int_report_fixed_header_h report_fixed_header;
    int_switch_id_h           int_switch_id;
    int_port_ids_h            int_port_ids;
    int_hop_latency_h         int_hop_latency;
    int_q_occupancy_h         int_q_occupancy;
    int_ingress_tstamp_h      int_ingress_tstamp;
    int_egress_tstamp_h       int_egress_tstamp;
    ethernet_h                ethernet;
    ipv4_h                    ipv4;
    udp_h                     udp;
    tcp_h                     tcp;
}

struct metadata_t {
    bit<16>     l4_src;
    bit<16>     l4_dst;
    mirror_h    mirror_md;
    MirrorId_t  mirror_session;
}

// ---------------------------------------------------------------------------
// Ingress parser
// ---------------------------------------------------------------------------

parser SwitchIngressParser(
    packet_in                        pkt,
    out headers_t                    hdr,
    out metadata_t                   meta,
    out ingress_intrinsic_metadata_t ig_intr_md)
{
    state start {
        pkt.extract(ig_intr_md);
        pkt.advance(PORT_METADATA_SIZE);
        meta.l4_src         = 0;
        meta.l4_dst         = 0;
        meta.mirror_session = 0;
        transition parse_ethernet;
    }

    state parse_ethernet {
        pkt.extract(hdr.ethernet);
        transition select(hdr.ethernet.ether_type) {
            ETHERTYPE_IPV4 : parse_ipv4;
            default        : accept;
        }
    }

    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            IP_PROTO_UDP : parse_udp;
            IP_PROTO_TCP : parse_tcp;
            default      : accept;
        }
    }

    state parse_udp {
        pkt.extract(hdr.udp);
        meta.l4_src = hdr.udp.src_port;
        meta.l4_dst = hdr.udp.dst_port;
        transition accept;
    }

    state parse_tcp {
        pkt.extract(hdr.tcp);
        meta.l4_src = hdr.tcp.src_port;
        meta.l4_dst = hdr.tcp.dst_port;
        transition accept;
    }
}

// ---------------------------------------------------------------------------
// Ingress control
// ---------------------------------------------------------------------------

control SwitchIngress(
    inout headers_t                                 hdr,
    inout metadata_t                                meta,
    in    ingress_intrinsic_metadata_t              ig_intr_md,
    in    ingress_intrinsic_metadata_from_parser_t  ig_prsr_md,
    inout ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md,
    inout ingress_intrinsic_metadata_for_tm_t       ig_tm_md)
{
    action drop() {
        ig_dprsr_md.drop_ctl = 0x1;
    }

    action forward(bit<9> port) {
        ig_tm_md.ucast_egress_port = port;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    table ipv4_fwd {
        key = { hdr.ipv4.dst_addr : exact; }
        actions = { forward; drop; }
        default_action = drop();
        size = 256;
    }

    action set_xd_clone(MirrorId_t session_id) {
        meta.mirror_session           = session_id;
        meta.mirror_md.setValid();
        meta.mirror_md.mirror_type    = MIRROR_TYPE_XD;
        meta.mirror_md.ingress_tstamp = ig_prsr_md.global_tstamp;
        meta.mirror_md.ingress_port   = (bit<16>)ig_intr_md.ingress_port;
        ig_dprsr_md.mirror_type       = (MirrorType_t)1;   // trigger I2E mirror
    }

    table tb_int_xd_watchlist {
        key = {
            hdr.ipv4.src_addr : ternary;
            hdr.ipv4.dst_addr : ternary;
            meta.l4_src       : ternary;
            meta.l4_dst       : ternary;
        }
        actions = { set_xd_clone; NoAction; }
        default_action = NoAction();
        size = 127;
    }

    apply {
        hdr.bridge_md.setValid();
        hdr.bridge_md.mirror_type    = 0;
        hdr.bridge_md.ingress_tstamp = ig_prsr_md.global_tstamp;
        hdr.bridge_md.ingress_port   = (bit<16>)ig_intr_md.ingress_port;

        if (hdr.ipv4.isValid()) {
            ipv4_fwd.apply();
        } else {
            drop();
        }
        if (hdr.udp.isValid() || hdr.tcp.isValid()) {
            tb_int_xd_watchlist.apply();
        }
    }
}

// ---------------------------------------------------------------------------
// Ingress deparser
// ---------------------------------------------------------------------------

control SwitchIngressDeparser(
    packet_out                                      pkt,
    inout headers_t                                 hdr,
    in    metadata_t                                meta,
    in    ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md)
{
    Mirror() mirror;

    apply {
        if (ig_dprsr_md.mirror_type == (MirrorType_t)1) {
            // Digest values come from metadata (set in the ingress action),
            // not constants, satisfying the Tofino digest field-list constraint.
            mirror.emit<mirror_h>(meta.mirror_session, meta.mirror_md);
        }
        pkt.emit(hdr.bridge_md);   // prefix on the main (non-clone) packet
        pkt.emit(hdr.ethernet);
        pkt.emit(hdr.ipv4);
        pkt.emit(hdr.udp);
        pkt.emit(hdr.tcp);
    }
}

// ---------------------------------------------------------------------------
// Egress parser
// ---------------------------------------------------------------------------

parser SwitchEgressParser(
    packet_in                       pkt,
    out headers_t                   hdr,
    out metadata_t                  meta,
    out egress_intrinsic_metadata_t eg_intr_md)
{
    state start {
        pkt.extract(eg_intr_md);
        meta.l4_src         = 0;
        meta.l4_dst         = 0;
        meta.mirror_session = 0;
        // First byte = mirror_type: 0 = bridged original, non-zero = XD clone.
        transition select((pkt.lookahead<bit<8>>())[7:0]) {
            8w0    : parse_bridge_md;
            default: parse_mirror_md;
        }
    }

    state parse_bridge_md {
        pkt.extract(hdr.bridge_md);
        transition parse_ethernet;
    }

    state parse_mirror_md {
        pkt.extract(hdr.mirror_md);
        transition parse_ethernet;
    }

    state parse_ethernet {
        pkt.extract(hdr.ethernet);
        transition select(hdr.ethernet.ether_type) {
            ETHERTYPE_IPV4 : parse_ipv4;
            default        : accept;
        }
    }

    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            IP_PROTO_UDP : parse_udp;
            IP_PROTO_TCP : parse_tcp;
            default      : accept;
        }
    }

    state parse_udp { pkt.extract(hdr.udp); transition accept; }
    state parse_tcp { pkt.extract(hdr.tcp); transition accept; }
}

// ---------------------------------------------------------------------------
// Egress control
// ---------------------------------------------------------------------------

control SwitchEgress(
    inout headers_t                                   hdr,
    inout metadata_t                                  meta,
    in    egress_intrinsic_metadata_t                 eg_intr_md,
    in    egress_intrinsic_metadata_from_parser_t     eg_prsr_md,
    inout egress_intrinsic_metadata_for_deparser_t    eg_dprsr_md,
    inout egress_intrinsic_metadata_for_output_port_t eg_oport_md)
{
    Register<bit<32>, bit<1>>(1) xd_seq_num_register;

    RegisterAction<bit<32>, bit<1>, bit<32>>(xd_seq_num_register)
        read_and_inc_xd_seq = {
            void apply(inout bit<32> value, out bit<32> result) {
                result = value;
                value  = value + 1;
            }
        };

    action send_xd_report(bit<48> dp_mac,
                          bit<32> dp_ip,
                          bit<48> collector_mac,
                          bit<32> collector_ip,
                          bit<16> collector_port,
                          bit<32> switch_id) {

        hdr.report_ethernet.setValid();
        hdr.report_ethernet.dst_addr   = collector_mac;
        hdr.report_ethernet.src_addr   = dp_mac;
        hdr.report_ethernet.ether_type = 0x0800;

        hdr.report_ipv4.setValid();
        hdr.report_ipv4.version        = 4;
        hdr.report_ipv4.ihl            = 5;
        hdr.report_ipv4.dscp           = 0;
        hdr.report_ipv4.ecn            = 0;
        hdr.report_ipv4.total_len      = 118;   // 20 + 8 + 16 + 14 + 20 + 8 + 32
        hdr.report_ipv4.identification = 0;
        hdr.report_ipv4.flags          = 0;
        hdr.report_ipv4.frag_offset    = 0;
        hdr.report_ipv4.ttl            = 64;
        hdr.report_ipv4.protocol       = 17;
        hdr.report_ipv4.hdr_checksum   = 0;
        hdr.report_ipv4.src_addr       = dp_ip;
        hdr.report_ipv4.dst_addr       = collector_ip;

        hdr.report_udp.setValid();
        hdr.report_udp.src_port  = 0;
        hdr.report_udp.dst_port  = collector_port;   // 6001
        hdr.report_udp.len       = 98;   // 8 + 16 + 14 + 20 + 8 + 32
        hdr.report_udp.checksum  = 0;    // 0 = no UDP checksum (valid for IPv4)

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
        hdr.report_fixed_header.seq_num          = read_and_inc_xd_seq.execute(0);
        hdr.report_fixed_header.ingress_tstamp   = (bit<32>)hdr.mirror_md.ingress_tstamp;

        hdr.int_switch_id.setValid();
        hdr.int_switch_id.switch_id = switch_id;

        hdr.int_port_ids.setValid();
        hdr.int_port_ids.ingress_port_id = hdr.mirror_md.ingress_port;
        hdr.int_port_ids.egress_port_id  = (bit<16>)eg_intr_md.egress_port;

        hdr.int_hop_latency.setValid();
        hdr.int_hop_latency.hop_latency =
            (bit<32>)(eg_prsr_md.global_tstamp - hdr.mirror_md.ingress_tstamp);

        hdr.int_q_occupancy.setValid();
        hdr.int_q_occupancy.q_id        = 0;
        hdr.int_q_occupancy.q_occupancy = (bit<24>)eg_intr_md.enq_qdepth;

        hdr.int_ingress_tstamp.setValid();
        hdr.int_ingress_tstamp.ingress_tstamp = (bit<64>)hdr.mirror_md.ingress_tstamp;

        hdr.int_egress_tstamp.setValid();
        hdr.int_egress_tstamp.egress_tstamp = (bit<64>)eg_prsr_md.global_tstamp;
    }

    table tb_int_xd_reporting {
        actions = { send_xd_report; NoAction; }
        default_action = NoAction();
        size = 512;
    }

    apply {
        if (hdr.mirror_md.isValid()) {
            tb_int_xd_reporting.apply();
        }
    }
}

// ---------------------------------------------------------------------------
// Egress deparser
// ---------------------------------------------------------------------------

control SwitchEgressDeparser(
    packet_out                                       pkt,
    inout headers_t                                  hdr,
    in    metadata_t                                 meta,
    in    egress_intrinsic_metadata_for_deparser_t   eg_dprsr_md)
{
    Checksum() ipv4_csum;

    apply {
        if (hdr.report_ipv4.isValid()) {
            hdr.report_ipv4.hdr_checksum = ipv4_csum.update({
                hdr.report_ipv4.version,
                hdr.report_ipv4.ihl,
                hdr.report_ipv4.dscp,
                hdr.report_ipv4.ecn,
                hdr.report_ipv4.total_len,
                hdr.report_ipv4.identification,
                hdr.report_ipv4.flags,
                hdr.report_ipv4.frag_offset,
                hdr.report_ipv4.ttl,
                hdr.report_ipv4.protocol,
                hdr.report_ipv4.src_addr,
                hdr.report_ipv4.dst_addr
            });
        }

        // bridge_md is intentionally NOT emitted here — it is stripped at egress.
        pkt.emit(hdr.report_ethernet);
        pkt.emit(hdr.report_ipv4);
        pkt.emit(hdr.report_udp);
        pkt.emit(hdr.report_fixed_header);
        pkt.emit(hdr.ethernet);
        pkt.emit(hdr.ipv4);
        pkt.emit(hdr.udp);
        pkt.emit(hdr.tcp);
        pkt.emit(hdr.int_switch_id);
        pkt.emit(hdr.int_port_ids);
        pkt.emit(hdr.int_hop_latency);
        pkt.emit(hdr.int_q_occupancy);
        pkt.emit(hdr.int_ingress_tstamp);
        pkt.emit(hdr.int_egress_tstamp);
    }
}

// ---------------------------------------------------------------------------
// Pipeline
// ---------------------------------------------------------------------------

Pipeline(
    SwitchIngressParser(),
    SwitchIngress(),
    SwitchIngressDeparser(),
    SwitchEgressParser(),
    SwitchEgress(),
    SwitchEgressDeparser()
) pipe;

Switch(pipe) main;

