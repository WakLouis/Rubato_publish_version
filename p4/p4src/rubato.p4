#include <core.p4>
#if __TARGET_TOFINO__ == 2
#include <t2na.p4>
#else
#include <tna.p4>
#endif

typedef bit<48> mac_addr_t;
typedef bit<16> ether_type_t;
typedef bit<32> ipv4_addr_t;
typedef bit<128> ipv6_addr_t;
typedef bit<10> bloom_index_t;
typedef bit<14> port_index_t;
typedef bit<5> wire_sampler_index_t;

const ether_type_t ETHERTYPE_IPV4 = 16w0x0800;
const ether_type_t ETHERTYPE_IPV6 = 16w0x86dd;
const ether_type_t ETHERTYPE_VLAN = 16w0x8100;
const bit<8> IP_PROTO_TCP = 8w6;
const bit<8> IP_PROTO_UDP = 8w17;
const bit<16> DNS_PORT = 16w53;
const bit<8> TRACE_REPLAY_TOS = 8w0xfc;

const bit<32> BLOOM_DEPTH = 1024;
// LPF telemetry covers q0-q31; TF2 forwarding may still select q0-q127.
const bit<32> PORT_STATE_DEPTH = 16384;
const bit<32> WIRE_SAMPLER_DEPTH = 32;
const QueueId_t DEFAULT_Q = 0;
const QueueId_t CONTROLLED_Q_MIN = 1;
const QueueId_t CONTROLLED_Q_MAX = 127;
const QueueId_t TELEMETRY_Q_MAX = 31;

const DigestType_t DNS_DIGEST_TYPE = 1;
const DigestType_t CANDIDATE_DIGEST_TYPE = 2;
const DigestType_t WIRE_OBSERVATION_DIGEST_TYPE = 3;

header ethernet_h {
    mac_addr_t dst_addr;
    mac_addr_t src_addr;
    ether_type_t ether_type;
}

header vlan_h {
    bit<3> pcp;
    bit<1> cfi;
    bit<12> vid;
    ether_type_t ether_type;
}

header ipv4_h {
    bit<4> version;
    bit<4> ihl;
    bit<8> diffserv;
    bit<16> total_len;
    bit<16> identification;
    bit<3> flags;
    bit<13> frag_offset;
    bit<8> ttl;
    bit<8> protocol;
    bit<16> hdr_checksum;
    ipv4_addr_t src_addr;
    ipv4_addr_t dst_addr;
}

header ipv6_h {
    bit<4> version;
    bit<8> traffic_class;
    bit<20> flow_label;
    bit<16> payload_len;
    bit<8> next_hdr;
    bit<8> hop_limit;
    ipv6_addr_t src_addr;
    ipv6_addr_t dst_addr;
}

header tcp_h {
    bit<16> src_port;
    bit<16> dst_port;
    bit<32> seq_no;
    bit<32> ack_no;
    bit<4> data_offset;
    bit<4> res;
    bit<8> flags;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgent_ptr;
}

header udp_h {
    bit<16> src_port;
    bit<16> dst_port;
    bit<16> hdr_length;
    bit<16> checksum;
}

header dns_h {
    bit<16> id;
    bit<16> flags;
    bit<16> qdcount;
    bit<16> ancount;
    bit<16> nscount;
    bit<16> arcount;
}

struct header_t {
    ethernet_h ethernet;
    vlan_h vlan;
    ipv4_h ipv4;
    ipv6_h ipv6;
    tcp_h tcp;
    udp_h udp;
    dns_h dns;
}

struct candidate_digest_t {
    bit<8> ip_version;
    bit<8> protocol;
    ipv6_addr_t src_ip;
    ipv6_addr_t dst_ip;
    bit<16> src_port;
    bit<16> dst_port;
    bloom_index_t hash0;
    bloom_index_t hash1;
    PortId_t ingress_port;
    bit<16> platform_id;
}

struct dns_digest_t {
    bit<8> ip_version;
    bit<8> protocol;
    ipv6_addr_t src_ip;
    ipv6_addr_t dst_ip;
    bit<16> src_port;
    bit<16> dst_port;
    bit<16> dns_id;
    bit<16> flags;
    bit<16> ancount;
    PortId_t ingress_port;
}

// IPv4 physical-ingress observation, not a classifier admission signal.
// Sequence and byte counts are per pipe and saturate: an epoch reaching
// 0xffffffff in either register is INVALID, never accepted as complete.
struct wire_observation_digest_t {
    bit<32> epoch_id;
    wire_sampler_index_t sampler_id;
    bit<32> sample_seq;
    bit<48> ingress_mac_tstamp;
    PortId_t ingress_port;
    ipv4_addr_t src_ip;
    ipv4_addr_t dst_ip;
    bit<16> total_len;
    bit<8> protocol;
    bit<16> src_port;
    bit<16> dst_port;
    bit<4> ipv4_ihl;
    bit<3> ipv4_flags;
    bit<13> ipv4_frag_offset;
    bit<1> l4_valid;
    bit<1> candidate_requested;
    bloom_index_t hash0;
    bloom_index_t hash1;
    bit<16> platform_id;
}

@flexible
struct metadata_t {
    bit<1> is_ipv4;
    bit<1> is_ipv6;
    bit<1> is_l4;
    bit<1> ba_hit;
    bit<1> bb_hit;
    bit<1> td_hit;
    bit<1> ti_hit;
    bit<1> candidate;
    bit<1> dns_response;
    bit<1> qoe_video_hit;
    bit<1> video_identity_hit;
    QueueId_t video_identity_qid;
    bit<1> ba0_value;
    bit<1> ba1_value;
    bit<1> cms_bank;
    bit<1> bank_select_key;
    QueueId_t qoe_qid;
    bit<2> qoe_class;
    bit<16> policy_version;
    bit<16> packet_bytes;
    bit<8> ip_version;
    bit<8> protocol;
    bit<16> src_port;
    bit<16> dst_port;
    ipv4_addr_t src_ip4;
    ipv4_addr_t dst_ip4;
    ipv6_addr_t src_ip6;
    ipv6_addr_t dst_ip6;
    bloom_index_t hash0;
    bloom_index_t hash1;
    PortId_t ingress_port;
    bit<16> platform_id;
    bit<1> wire_observe;
    bit<32> wire_epoch_id;
    wire_sampler_index_t wire_sampler_id;
    bit<32> wire_sample_seq;
    bit<32> wire_bytes_total;
    bit<48> wire_mac_tstamp;
    bit<1> wire_candidate_requested;
}

@flexible
struct egress_metadata_t {
    bit<32> qdepth_sample;
    bit<32> short_lpf;
    bit<32> long_lpf;
    port_index_t port_index;
}

parser SwitchIngressParser(
        packet_in pkt,
        out header_t hdr,
        out metadata_t md,
        out ingress_intrinsic_metadata_t ig_intr_md) {

    state start {
        md.is_ipv4 = 0;
        md.is_ipv6 = 0;
        md.is_l4 = 0;
        md.ba_hit = 0;
        md.bb_hit = 0;
        md.td_hit = 0;
        md.ti_hit = 0;
        md.candidate = 0;
        md.dns_response = 0;
        md.qoe_video_hit = 0;
        md.video_identity_hit = 0;
        md.video_identity_qid = CONTROLLED_Q_MIN;
        md.ba0_value = 0;
        md.ba1_value = 0;
        md.cms_bank = 0;
        md.bank_select_key = 0;
        md.qoe_qid = CONTROLLED_Q_MIN;
        md.qoe_class = 0;
        md.policy_version = 0;
        md.packet_bytes = 0;
        md.ip_version = 0;
        md.protocol = 0;
        md.src_port = 0;
        md.dst_port = 0;
        md.src_ip4 = 0;
        md.dst_ip4 = 0;
        md.src_ip6 = 0;
        md.dst_ip6 = 0;
        md.hash0 = 0;
        md.hash1 = 0;
        md.ingress_port = 0;
        md.platform_id = 0;
        md.wire_observe = 0;
        md.wire_epoch_id = 0;
        md.wire_sampler_id = 0;
        md.wire_sample_seq = 0;
        md.wire_bytes_total = 0;
        md.wire_mac_tstamp = 0;
        md.wire_candidate_requested = 0;

        pkt.extract(ig_intr_md);
        transition skip_port_metadata;
    }

    state skip_port_metadata {
        pkt.advance(PORT_METADATA_SIZE);
        transition parse_ethernet;
    }

    state parse_ethernet {
        pkt.extract(hdr.ethernet);
        transition select(hdr.ethernet.ether_type) {
            ETHERTYPE_VLAN: parse_vlan;
            ETHERTYPE_IPV4: parse_ipv4;
            ETHERTYPE_IPV6: parse_ipv6;
            default: accept;
        }
    }

    state parse_vlan {
        pkt.extract(hdr.vlan);
        transition select(hdr.vlan.ether_type) {
            ETHERTYPE_IPV4: parse_ipv4;
            ETHERTYPE_IPV6: parse_ipv6;
            default: accept;
        }
    }

    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            IP_PROTO_TCP: parse_tcp;
            IP_PROTO_UDP: parse_udp;
            default: accept;
        }
    }

    state parse_ipv6 {
        pkt.extract(hdr.ipv6);
        transition select(hdr.ipv6.next_hdr) {
            IP_PROTO_TCP: parse_tcp;
            IP_PROTO_UDP: parse_udp;
            default: accept;
        }
    }

    state parse_tcp {
        pkt.extract(hdr.tcp);
        transition accept;
    }

    state parse_udp {
        pkt.extract(hdr.udp);
        transition select(hdr.udp.src_port) {
            DNS_PORT: parse_dns;
            default: parse_udp_dst;
        }
    }

    state parse_udp_dst {
        transition select(hdr.udp.dst_port) {
            DNS_PORT: parse_dns;
            default: accept;
        }
    }

    state parse_dns {
        pkt.extract(hdr.dns);
        transition accept;
    }
}

control SwitchIngressDeparser(
        packet_out pkt,
        inout header_t hdr,
        in metadata_t md,
        in ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md) {

    Digest<dns_digest_t>() dns_digest;
    Digest<candidate_digest_t>() candidate_digest;
    Digest<wire_observation_digest_t>() wire_observation_digest;

    apply {
        if (ig_dprsr_md.digest_type == WIRE_OBSERVATION_DIGEST_TYPE) {
            wire_observation_digest.pack({
                md.wire_epoch_id,
                md.wire_sampler_id,
                md.wire_sample_seq,
                md.wire_mac_tstamp,
                md.ingress_port,
                hdr.ipv4.src_addr,
                hdr.ipv4.dst_addr,
                hdr.ipv4.total_len,
                hdr.ipv4.protocol,
                md.src_port,
                md.dst_port,
                hdr.ipv4.ihl,
                hdr.ipv4.flags,
                hdr.ipv4.frag_offset,
                md.is_l4,
                md.wire_candidate_requested,
                md.hash0,
                md.hash1,
                md.platform_id
            });
        } else if (ig_dprsr_md.digest_type == DNS_DIGEST_TYPE) {
            dns_digest.pack({
                md.ip_version,
                md.protocol,
                md.src_ip6,
                md.dst_ip6,
                md.src_port,
                md.dst_port,
                hdr.dns.id,
                hdr.dns.flags,
                hdr.dns.ancount,
                md.ingress_port
            });
        } else if (ig_dprsr_md.digest_type == CANDIDATE_DIGEST_TYPE) {
            candidate_digest.pack({
                md.ip_version,
                md.protocol,
                md.src_ip6,
                md.dst_ip6,
                md.src_port,
                md.dst_port,
                md.hash0,
                md.hash1,
                md.ingress_port,
                md.platform_id
            });
        }

        pkt.emit(hdr.ethernet);
        pkt.emit(hdr.vlan);
        pkt.emit(hdr.ipv4);
        pkt.emit(hdr.ipv6);
        pkt.emit(hdr.tcp);
        pkt.emit(hdr.udp);
        pkt.emit(hdr.dns);
    }
}

control SwitchIngress(
        inout header_t hdr,
        inout metadata_t md,
        in ingress_intrinsic_metadata_t ig_intr_md,
        in ingress_intrinsic_metadata_from_parser_t ig_prsr_md,
        inout ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md,
        inout ingress_intrinsic_metadata_for_tm_t ig_tm_md) {

    CRCPolynomial<bit<32>>(0xf0cb4ab9, false, false, false, 0x00, 0x00) poly0;
    CRCPolynomial<bit<32>>(0x7b7138fd, false, false, false, 0x00, 0x00) poly1;
    Hash<bloom_index_t>(HashAlgorithm_t.CUSTOM, poly0) hash0;
    Hash<bloom_index_t>(HashAlgorithm_t.CUSTOM, poly1) hash1;

    Register<bit<1>, bloom_index_t>(BLOOM_DEPTH) ba0;
    Register<bit<1>, bloom_index_t>(BLOOM_DEPTH) ba1;

    Register<bit<32>, bloom_index_t>(BLOOM_DEPTH) cms_a0;
    Register<bit<32>, bloom_index_t>(BLOOM_DEPTH) cms_a1;
    Register<bit<32>, bloom_index_t>(BLOOM_DEPTH) cms_b0;
    Register<bit<32>, bloom_index_t>(BLOOM_DEPTH) cms_b1;

    Register<bit<32>, wire_sampler_index_t>(WIRE_SAMPLER_DEPTH) wire_packet_count;
    Register<bit<32>, wire_sampler_index_t>(WIRE_SAMPLER_DEPTH) wire_ipv4_byte_count;
    RegisterAction<bit<32>, wire_sampler_index_t, bit<32>>(wire_packet_count) wire_next_seq = {
        void apply(inout bit<32> value, out bit<32> result) {
            value = value |+| 32w1;
            result = value;
        }
    };
    RegisterAction<bit<32>, wire_sampler_index_t, bit<32>>(wire_ipv4_byte_count) wire_add_bytes = {
        void apply(inout bit<32> value, out bit<32> result) {
            value = value |+| (bit<32>) md.packet_bytes;
            result = value;
        }
    };

    action enable_wire_observation(bit<32> epoch_id, wire_sampler_index_t sampler_id) {
        md.wire_observe = 1w1;
        md.wire_epoch_id = epoch_id;
        md.wire_sampler_id = sampler_id;
    }

    table wire_observation_filter {
        key = {
            md.ingress_port: exact;
            hdr.ipv4.src_addr: exact;
        }
        actions = { enable_wire_observation; NoAction; }
        const size = 16;
        const default_action = NoAction;
    }

    action allocate_wire_seq() {
        md.wire_sample_seq = wire_next_seq.execute(md.wire_sampler_id);
    }

    action count_wire_bytes() {
        md.wire_bytes_total = wire_add_bytes.execute(md.wire_sampler_id);
    }

    RegisterAction<bit<1>, bloom_index_t, bit<1>>(ba0) ba0_read = {
        void apply(inout bit<1> value, out bit<1> result) { result = value; }
    };
    RegisterAction<bit<1>, bloom_index_t, bit<1>>(ba1) ba1_read = {
        void apply(inout bit<1> value, out bit<1> result) { result = value; }
    };
    RegisterAction<bit<32>, bloom_index_t, bit<32>>(cms_a0) cms_a0_inc = {
        void apply(inout bit<32> value, out bit<32> result) {
            value = value |+| (bit<32>) md.packet_bytes;
            result = value;
        }
    };
    RegisterAction<bit<32>, bloom_index_t, bit<32>>(cms_a1) cms_a1_inc = {
        void apply(inout bit<32> value, out bit<32> result) {
            value = value |+| (bit<32>) md.packet_bytes;
            result = value;
        }
    };
    RegisterAction<bit<32>, bloom_index_t, bit<32>>(cms_b0) cms_b0_inc = {
        void apply(inout bit<32> value, out bit<32> result) {
            value = value |+| (bit<32>) md.packet_bytes;
            result = value;
        }
    };
    RegisterAction<bit<32>, bloom_index_t, bit<32>>(cms_b1) cms_b1_inc = {
        void apply(inout bit<32> value, out bit<32> result) {
            value = value |+| (bit<32>) md.packet_bytes;
            result = value;
        }
    };

    action set_port(PortId_t port) {
        ig_tm_md.ucast_egress_port = port;
        ig_dprsr_md.drop_ctl = 3w0;
    }

    action drop_packet() {
        ig_dprsr_md.drop_ctl = 3w1;
    }

    action mark_td(bit<16> platform_id) {
        md.td_hit = 1w1;
        md.platform_id = platform_id;
    }

    action mark_ti(bit<16> platform_id) {
        md.ti_hit = 1w1;
        md.platform_id = platform_id;
    }

    // Independent of expiring exact-flow shaping policies. A qid=0 observer
    // entry must never override this identity's video queue.
    action mark_video_ip(bit<16> platform_id, QueueId_t qid) {
        md.td_hit = 1w1;
        md.video_identity_hit = 1w1;
        md.video_identity_qid = qid;
        md.platform_id = platform_id;
    }

    action force_video(bit<16> platform_id) {
        md.ba_hit = 1w1;
        md.qoe_video_hit = 1w1;
        md.qoe_qid = CONTROLLED_Q_MIN;
        md.platform_id = platform_id;
    }

    action set_qoe_video(QueueId_t qid, bit<16> policy_version, bit<16> platform_id) {
        md.ba_hit = 1w1;
        md.qoe_video_hit = 1w1;
        md.qoe_qid = qid;
        md.policy_version = policy_version;
        md.platform_id = platform_id;
    }

    action set_trace_replay_qid(QueueId_t qid) {
        ig_tm_md.qid = qid;
    }

    action mark_bb() {
        md.bb_hit = 1w1;
    }

    action set_cms_bank(bit<1> bank) {
        md.cms_bank = bank;
    }

    action update_cms_a0() {
        cms_a0_inc.execute(md.hash0);
    }

    action update_cms_a1() {
        cms_a1_inc.execute(md.hash1);
    }

    action update_cms_b0() {
        cms_b0_inc.execute(md.hash0);
    }

    action update_cms_b1() {
        cms_b1_inc.execute(md.hash1);
    }

    table dmac {
        key = { ig_intr_md.ingress_port: exact; }
        actions = { set_port; drop_packet; NoAction; }
        const size = 4;
        const default_action = drop_packet;
    }

    table td_ip4_exact {
        key = { hdr.ipv4.src_addr: exact; }
        actions = { mark_td; mark_video_ip; NoAction; }
        const size = 65536;
        const default_action = NoAction;
    }

    table td_ip6_exact {
        key = { hdr.ipv6.src_addr: exact; }
        actions = { mark_td; mark_video_ip; NoAction; }
        const size = 65536;
        const default_action = NoAction;
    }

    table ti_ip4_lpm {
        key = { hdr.ipv4.src_addr: lpm; }
        actions = { mark_ti; NoAction; }
        const size = 4096;
        const default_action = NoAction;
    }

    table ti_ip6_lpm {
        key = { hdr.ipv6.src_addr: lpm; }
        actions = { mark_ti; NoAction; }
        const size = 4096;
        const default_action = NoAction;
    }

    table force_video4 {
        key = {
            hdr.ipv4.src_addr: exact;
            hdr.ipv4.dst_addr: exact;
            md.protocol: exact;
            md.dst_port: exact;
        }
        actions = { force_video; NoAction; }
        const size = 64;
        const default_action = NoAction;
    }

    table force_video6 {
        key = {
            hdr.ipv6.src_addr: exact;
            hdr.ipv6.dst_addr: exact;
            md.protocol: exact;
            md.dst_port: exact;
        }
        actions = { force_video; NoAction; }
        const size = 64;
        const default_action = NoAction;
    }

    table qoe_video4 {
        key = {
            hdr.ipv4.src_addr: exact;
            hdr.ipv4.dst_addr: exact;
            md.src_port: exact;
            md.dst_port: exact;
            md.protocol: exact;
        }
        actions = { set_qoe_video; NoAction; }
        const size = 8192;
        const default_action = NoAction;
    }

    table qoe_video6 {
        key = {
            hdr.ipv6.src_addr: exact;
            hdr.ipv6.dst_addr: exact;
            md.src_port: exact;
            md.dst_port: exact;
            md.protocol: exact;
        }
        actions = { set_qoe_video; NoAction; }
        const size = 8192;
        const default_action = NoAction;
    }

    table trace_replay_qid4 {
        key = {
            hdr.ipv4.diffserv: ternary;
            hdr.tcp.dst_port: exact;
        }
        actions = { set_trace_replay_qid; NoAction; }
        const size = 31;
        const default_action = NoAction;
        const entries = {
            (TRACE_REPLAY_TOS &&& 8w0xfc, 16w5101): set_trace_replay_qid(1);
            (TRACE_REPLAY_TOS &&& 8w0xfc, 16w5102): set_trace_replay_qid(2);
            (TRACE_REPLAY_TOS &&& 8w0xfc, 16w5103): set_trace_replay_qid(3);
            (TRACE_REPLAY_TOS &&& 8w0xfc, 16w5104): set_trace_replay_qid(4);
            (TRACE_REPLAY_TOS &&& 8w0xfc, 16w5105): set_trace_replay_qid(5);
            (TRACE_REPLAY_TOS &&& 8w0xfc, 16w5106): set_trace_replay_qid(6);
            (TRACE_REPLAY_TOS &&& 8w0xfc, 16w5107): set_trace_replay_qid(7);
            (TRACE_REPLAY_TOS &&& 8w0xfc, 16w5108): set_trace_replay_qid(8);
            (TRACE_REPLAY_TOS &&& 8w0xfc, 16w5109): set_trace_replay_qid(9);
            (TRACE_REPLAY_TOS &&& 8w0xfc, 16w5110): set_trace_replay_qid(10);
            (TRACE_REPLAY_TOS &&& 8w0xfc, 16w5111): set_trace_replay_qid(11);
            (TRACE_REPLAY_TOS &&& 8w0xfc, 16w5112): set_trace_replay_qid(12);
            (TRACE_REPLAY_TOS &&& 8w0xfc, 16w5113): set_trace_replay_qid(13);
            (TRACE_REPLAY_TOS &&& 8w0xfc, 16w5114): set_trace_replay_qid(14);
            (TRACE_REPLAY_TOS &&& 8w0xfc, 16w5115): set_trace_replay_qid(15);
            (TRACE_REPLAY_TOS &&& 8w0xfc, 16w5116): set_trace_replay_qid(16);
            (TRACE_REPLAY_TOS &&& 8w0xfc, 16w5117): set_trace_replay_qid(17);
            (TRACE_REPLAY_TOS &&& 8w0xfc, 16w5118): set_trace_replay_qid(18);
            (TRACE_REPLAY_TOS &&& 8w0xfc, 16w5119): set_trace_replay_qid(19);
            (TRACE_REPLAY_TOS &&& 8w0xfc, 16w5120): set_trace_replay_qid(20);
            (TRACE_REPLAY_TOS &&& 8w0xfc, 16w5121): set_trace_replay_qid(21);
            (TRACE_REPLAY_TOS &&& 8w0xfc, 16w5122): set_trace_replay_qid(22);
            (TRACE_REPLAY_TOS &&& 8w0xfc, 16w5123): set_trace_replay_qid(23);
            (TRACE_REPLAY_TOS &&& 8w0xfc, 16w5124): set_trace_replay_qid(24);
            (TRACE_REPLAY_TOS &&& 8w0xfc, 16w5125): set_trace_replay_qid(25);
            (TRACE_REPLAY_TOS &&& 8w0xfc, 16w5126): set_trace_replay_qid(26);
            (TRACE_REPLAY_TOS &&& 8w0xfc, 16w5127): set_trace_replay_qid(27);
            (TRACE_REPLAY_TOS &&& 8w0xfc, 16w5128): set_trace_replay_qid(28);
            (TRACE_REPLAY_TOS &&& 8w0xfc, 16w5129): set_trace_replay_qid(29);
            (TRACE_REPLAY_TOS &&& 8w0xfc, 16w5130): set_trace_replay_qid(30);
            (TRACE_REPLAY_TOS &&& 8w0xfc, 16w5131): set_trace_replay_qid(31);
        }
    }

    table rejected_flow4 {
        key = {
            hdr.ipv4.src_addr: exact;
            hdr.ipv4.dst_addr: exact;
            md.src_port: exact;
            md.dst_port: exact;
            md.protocol: exact;
        }
        actions = { mark_bb; NoAction; }
        const size = 8192;
        const default_action = NoAction;
    }

    table rejected_flow6 {
        key = {
            hdr.ipv6.src_addr: exact;
            hdr.ipv6.dst_addr: exact;
            md.src_port: exact;
            md.dst_port: exact;
            md.protocol: exact;
        }
        actions = { mark_bb; NoAction; }
        const size = 8192;
        const default_action = NoAction;
    }

    table cms_bank_select {
        key = { md.bank_select_key: exact; }
        actions = { set_cms_bank; }
        const size = 1;
        default_action = set_cms_bank(0);
    }

    action init_ipv4() {
        md.is_ipv4 = 1w1;
        md.ip_version = 4;
        md.src_ip4 = hdr.ipv4.src_addr;
        md.dst_ip4 = hdr.ipv4.dst_addr;
        md.src_ip6 = (ipv6_addr_t) hdr.ipv4.src_addr;
        md.dst_ip6 = (ipv6_addr_t) hdr.ipv4.dst_addr;
        md.packet_bytes = hdr.ipv4.total_len;
    }

    action init_ipv6() {
        md.is_ipv6 = 1w1;
        md.ip_version = 6;
        md.src_ip6 = hdr.ipv6.src_addr;
        md.dst_ip6 = hdr.ipv6.dst_addr;
        md.packet_bytes = hdr.ipv6.payload_len + 40;
    }

    action init_tcp() {
        md.is_l4 = 1w1;
        md.protocol = IP_PROTO_TCP;
        md.src_port = hdr.tcp.src_port;
        md.dst_port = hdr.tcp.dst_port;
    }

    action init_udp() {
        md.is_l4 = 1w1;
        md.protocol = IP_PROTO_UDP;
        md.src_port = hdr.udp.src_port;
        md.dst_port = hdr.udp.dst_port;
    }

    action compute_hash() {
        md.hash0 = hash0.get({
            md.src_ip6,
            md.dst_ip6,
            md.src_port,
            md.dst_port,
            md.protocol,
            md.ip_version
        });
        md.hash1 = hash1.get({
            md.src_ip6,
            md.dst_ip6,
            md.src_port,
            md.dst_port,
            md.protocol,
            md.ip_version
        });
    }

    action read_ba0() {
        md.ba0_value = ba0_read.execute(md.hash0);
    }

    action read_ba1() {
        md.ba1_value = ba1_read.execute(md.hash1);
    }

    action resolve_bloom_hits() {
        md.ba_hit = md.ba0_value & md.ba1_value;
    }

    apply {
        ig_dprsr_md.digest_type = 0;
        ig_dprsr_md.drop_ctl = 3w0;
        ig_tm_md.copy_to_cpu = 1w0;
        ig_tm_md.qid = DEFAULT_Q;
        ig_tm_md.bypass_egress = 1w0;
        md.ingress_port = ig_intr_md.ingress_port;

        if (hdr.tcp.isValid()) {
            init_tcp();
        } else if (hdr.udp.isValid()) {
            init_udp();
        }

        if (hdr.ipv4.isValid()) {
            init_ipv4();
            if (md.is_l4 == 1w1) {
                td_ip4_exact.apply();
                ti_ip4_lpm.apply();
            }
        } else if (hdr.ipv6.isValid()) {
            init_ipv6();
            if (md.is_l4 == 1w1) {
                td_ip6_exact.apply();
                ti_ip6_lpm.apply();
            }
        }
        dmac.apply();

        if ((md.is_l4 == 1w1) && ((md.is_ipv4 == 1w1) || (md.is_ipv6 == 1w1))) {
            compute_hash();
            read_ba0();
            read_ba1();
            resolve_bloom_hits();
            if (md.is_ipv4 == 1w1) {
                rejected_flow4.apply();
                force_video4.apply();
                qoe_video4.apply();
            } else {
                rejected_flow6.apply();
                force_video6.apply();
                qoe_video6.apply();
            }
            // Confirmed flows remain observable; ba_hit suppresses only digests.
            if (((md.bb_hit == 1w0) || (md.video_identity_hit == 1w1)) &&
                    ((md.td_hit == 1w1) || (md.ti_hit == 1w1) || (md.qoe_video_hit == 1w1)) &&
                    !hdr.dns.isValid()) {
                cms_bank_select.apply();
                md.candidate = 1w1;
                if (md.ba_hit == 1w0) {
                    ig_dprsr_md.digest_type = CANDIDATE_DIGEST_TYPE;
                }
            }
            // Direct conditional actions avoid exposing compiler-folded constant
            // match keys as inconsistent BFRT tables on SDE 9.7.
            if (md.candidate == 1w1) {
                if (md.cms_bank == 1w0) {
                    update_cms_a0();
                    update_cms_a1();
                } else {
                    update_cms_b0();
                    update_cms_b1();
                }
            }
        }

        if ((md.qoe_video_hit == 1w1) && (md.qoe_qid != DEFAULT_Q)) {
            ig_tm_md.qid = md.qoe_qid;
        } else if (md.video_identity_hit == 1w1) {
            ig_tm_md.qid = md.video_identity_qid;
        } else {
            ig_tm_md.qid = DEFAULT_Q;
        }
        // Exp#2 replays already selected media flows.  A sender-only DSCP
        // marker plus dedicated ports demultiplexes them into q1--q31 without
        // coupling the shaping experiment to the Exp#1 classifier.
#ifdef RUBATO_TRACE_REPLAY
        trace_replay_qid4.apply();
#endif
        if (hdr.dns.isValid() && hdr.dns.flags[15:15] == 1w1) {
            md.dns_response = 1w1;
            // DNS shadow is collected on NIC2's normal forwarding port
            // (front-panel 10/0, devport 52).  The NIC2 agent sees the full
            // DNS payload there and posts mappings to the Tofino controller.
            // copy_to_cpu stays disabled; devport 52 is the observation port.
            // BFRT digest is not used for DNS because it cannot carry the full
            // answer payload needed to parse A/AAAA/CNAME records.
        }

        // Observe before traffic-manager enqueue. Do not change forwarding,
        // CMS selection, Bloom state or queue assignment. The timestamp is
        // the ingress MAC timestamp on both TNA and T2NA, NOT CPU receipt time.
        if (hdr.ipv4.isValid()) {
            wire_observation_filter.apply();
            if (md.wire_observe == 1w1) {
                md.wire_mac_tstamp = ig_intr_md.ingress_mac_tstamp;
                allocate_wire_seq();
                count_wire_bytes();
                if (ig_dprsr_md.digest_type == CANDIDATE_DIGEST_TYPE) {
                    md.wire_candidate_requested = 1w1;
                }
                // One deparser pack per packet: collector dispatches the
                // embedded candidate iff candidate_requested, never all traces.
                ig_dprsr_md.digest_type = WIRE_OBSERVATION_DIGEST_TYPE;
            }
        }
    }
}

parser SwitchEgressParser(
        packet_in pkt,
        out header_t hdr,
        out egress_metadata_t eg_md,
        out egress_intrinsic_metadata_t eg_intr_md) {

    state start {
        eg_md.qdepth_sample = 0;
        eg_md.short_lpf = 0;
        eg_md.long_lpf = 0;
        eg_md.port_index = 0;
        pkt.extract(eg_intr_md);
        transition parse_ethernet;
    }

    state parse_ethernet {
        pkt.extract(hdr.ethernet);
        transition select(hdr.ethernet.ether_type) {
            ETHERTYPE_VLAN: parse_vlan;
            ETHERTYPE_IPV4: parse_ipv4;
            ETHERTYPE_IPV6: parse_ipv6;
            default: accept;
        }
    }

    state parse_vlan {
        pkt.extract(hdr.vlan);
        transition select(hdr.vlan.ether_type) {
            ETHERTYPE_IPV4: parse_ipv4;
            ETHERTYPE_IPV6: parse_ipv6;
            default: accept;
        }
    }

    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            IP_PROTO_TCP: parse_tcp;
            IP_PROTO_UDP: parse_udp;
            default: accept;
        }
    }

    state parse_ipv6 {
        pkt.extract(hdr.ipv6);
        transition select(hdr.ipv6.next_hdr) {
            IP_PROTO_TCP: parse_tcp;
            IP_PROTO_UDP: parse_udp;
            default: accept;
        }
    }

    state parse_tcp {
        pkt.extract(hdr.tcp);
        transition accept;
    }

    state parse_udp {
        pkt.extract(hdr.udp);
        transition select(hdr.udp.src_port) {
            DNS_PORT: parse_dns;
            default: parse_udp_dst;
        }
    }

    state parse_udp_dst {
        transition select(hdr.udp.dst_port) {
            DNS_PORT: parse_dns;
            default: accept;
        }
    }

    state parse_dns {
        pkt.extract(hdr.dns);
        transition accept;
    }
}

control SwitchEgress(
        inout header_t hdr,
        inout egress_metadata_t eg_md,
        in egress_intrinsic_metadata_t eg_intr_md,
        in egress_intrinsic_metadata_from_parser_t eg_prsr_md,
        inout egress_intrinsic_metadata_for_deparser_t eg_dprsr_md,
        inout egress_intrinsic_metadata_for_output_port_t eg_oport_md) {

    Lpf<bit<32>, port_index_t>(PORT_STATE_DEPTH) video_qdepth_short_lpf;
    Lpf<bit<32>, port_index_t>(PORT_STATE_DEPTH) video_qdepth_long_lpf;
    Register<bit<32>, port_index_t>(PORT_STATE_DEPTH) video_qdepth_last_sample;
    Register<bit<32>, port_index_t>(PORT_STATE_DEPTH) video_qdepth_short_value;
    Register<bit<32>, port_index_t>(PORT_STATE_DEPTH) video_qdepth_long_value;
    Register<bit<32>, port_index_t>(PORT_STATE_DEPTH) video_egress_bytes;
    Register<bit<32>, port_index_t>(PORT_STATE_DEPTH) queue_egress_packets;
    Register<bit<32>, port_index_t>(PORT_STATE_DEPTH) queue_residence_max;

    RegisterAction<bit<32>, port_index_t, bit<32>>(queue_egress_packets) add_egress_packet = {
        void apply(inout bit<32> value, out bit<32> result) {
            value = value + 1;
            result = value;
        }
    };

    RegisterAction<bit<32>, port_index_t, bit<32>>(queue_residence_max) record_residence = {
        void apply(inout bit<32> value, out bit<32> result) {
            if (value < (bit<32>) eg_intr_md.deq_timedelta) {
                value = (bit<32>) eg_intr_md.deq_timedelta;
            }
            result = value;
        }
    };

    RegisterAction<bit<32>, port_index_t, bit<32>>(video_qdepth_last_sample) update_last_sample = {
        void apply(inout bit<32> value, out bit<32> result) {
            value = eg_md.qdepth_sample;
            result = value;
        }
    };

    RegisterAction<bit<32>, port_index_t, bit<32>>(video_qdepth_short_value) store_short_lpf = {
        void apply(inout bit<32> value, out bit<32> result) {
            value = eg_md.short_lpf;
            result = value;
        }
    };

    RegisterAction<bit<32>, port_index_t, bit<32>>(video_qdepth_long_value) store_long_lpf = {
        void apply(inout bit<32> value, out bit<32> result) {
            value = eg_md.long_lpf;
            result = value;
        }
    };

    RegisterAction<bit<32>, port_index_t, bit<32>>(video_egress_bytes) add_video_bytes = {
        void apply(inout bit<32> value, out bit<32> result) {
            value = value + (bit<32>) eg_intr_md.pkt_length;
            result = value;
        }
    };

    action update_short_lpf() {
        eg_md.short_lpf = video_qdepth_short_lpf.execute(eg_md.qdepth_sample, eg_md.port_index);
    }

    action update_long_lpf() {
        eg_md.long_lpf = video_qdepth_long_lpf.execute(eg_md.qdepth_sample, eg_md.port_index);
    }

    action set_video_state_index(port_index_t index_base) {
        eg_md.port_index = ((port_index_t) eg_intr_md.egress_port) + index_base;
    }

    table video_state_index_select {
        key = { eg_intr_md.egress_qid: exact; }
        actions = { set_video_state_index; NoAction; }
        const size = 32;
        const default_action = NoAction;
        const entries = {
            (0): set_video_state_index(0);
            (1): set_video_state_index(512);
            (2): set_video_state_index(1024);
            (3): set_video_state_index(1536);
            (4): set_video_state_index(2048);
            (5): set_video_state_index(2560);
            (6): set_video_state_index(3072);
            (7): set_video_state_index(3584);
            (8): set_video_state_index(4096);
            (9): set_video_state_index(4608);
            (10): set_video_state_index(5120);
            (11): set_video_state_index(5632);
            (12): set_video_state_index(6144);
            (13): set_video_state_index(6656);
            (14): set_video_state_index(7168);
            (15): set_video_state_index(7680);
            (16): set_video_state_index(8192);
            (17): set_video_state_index(8704);
            (18): set_video_state_index(9216);
            (19): set_video_state_index(9728);
            (20): set_video_state_index(10240);
            (21): set_video_state_index(10752);
            (22): set_video_state_index(11264);
            (23): set_video_state_index(11776);
            (24): set_video_state_index(12288);
            (25): set_video_state_index(12800);
            (26): set_video_state_index(13312);
            (27): set_video_state_index(13824);
            (28): set_video_state_index(14336);
            (29): set_video_state_index(14848);
            (30): set_video_state_index(15360);
            (31): set_video_state_index(15872);
        }
    }

    table video_short_lpf_update {
        key = { eg_intr_md.egress_qid: exact; }
        actions = { update_short_lpf; NoAction; }
        filters = video_qdepth_short_lpf;
        const size = 31;
        const default_action = NoAction;
        const entries = {
            (1): update_short_lpf();
            (2): update_short_lpf();
            (3): update_short_lpf();
            (4): update_short_lpf();
            (5): update_short_lpf();
            (6): update_short_lpf();
            (7): update_short_lpf();
            (8): update_short_lpf();
            (9): update_short_lpf();
            (10): update_short_lpf();
            (11): update_short_lpf();
            (12): update_short_lpf();
            (13): update_short_lpf();
            (14): update_short_lpf();
            (15): update_short_lpf();
            (16): update_short_lpf();
            (17): update_short_lpf();
            (18): update_short_lpf();
            (19): update_short_lpf();
            (20): update_short_lpf();
            (21): update_short_lpf();
            (22): update_short_lpf();
            (23): update_short_lpf();
            (24): update_short_lpf();
            (25): update_short_lpf();
            (26): update_short_lpf();
            (27): update_short_lpf();
            (28): update_short_lpf();
            (29): update_short_lpf();
            (30): update_short_lpf();
            (31): update_short_lpf();
        }
    }

    table video_long_lpf_update {
        key = { eg_intr_md.egress_qid: exact; }
        actions = { update_long_lpf; NoAction; }
        filters = video_qdepth_long_lpf;
        const size = 31;
        const default_action = NoAction;
        const entries = {
            (1): update_long_lpf();
            (2): update_long_lpf();
            (3): update_long_lpf();
            (4): update_long_lpf();
            (5): update_long_lpf();
            (6): update_long_lpf();
            (7): update_long_lpf();
            (8): update_long_lpf();
            (9): update_long_lpf();
            (10): update_long_lpf();
            (11): update_long_lpf();
            (12): update_long_lpf();
            (13): update_long_lpf();
            (14): update_long_lpf();
            (15): update_long_lpf();
            (16): update_long_lpf();
            (17): update_long_lpf();
            (18): update_long_lpf();
            (19): update_long_lpf();
            (20): update_long_lpf();
            (21): update_long_lpf();
            (22): update_long_lpf();
            (23): update_long_lpf();
            (24): update_long_lpf();
            (25): update_long_lpf();
            (26): update_long_lpf();
            (27): update_long_lpf();
            (28): update_long_lpf();
            (29): update_long_lpf();
            (30): update_long_lpf();
            (31): update_long_lpf();
        }
    }

    apply {
        if (eg_intr_md.egress_qid <= TELEMETRY_Q_MAX) {
            video_state_index_select.apply();
            eg_md.qdepth_sample = (bit<32>) eg_intr_md.enq_qdepth;
            update_last_sample.execute(eg_md.port_index);
            video_short_lpf_update.apply();
            video_long_lpf_update.apply();
            store_short_lpf.execute(eg_md.port_index);
            store_long_lpf.execute(eg_md.port_index);
            add_video_bytes.execute(eg_md.port_index);
            add_egress_packet.execute(eg_md.port_index);
            record_residence.execute(eg_md.port_index);
        }
    }
}

control SwitchEgressDeparser(
        packet_out pkt,
        inout header_t hdr,
        in egress_metadata_t eg_md,
        in egress_intrinsic_metadata_for_deparser_t eg_dprsr_md) {
    apply {
        pkt.emit(hdr.ethernet);
        pkt.emit(hdr.vlan);
        pkt.emit(hdr.ipv4);
        pkt.emit(hdr.ipv6);
        pkt.emit(hdr.tcp);
        pkt.emit(hdr.udp);
        pkt.emit(hdr.dns);
    }
}

Pipeline(SwitchIngressParser(),
         SwitchIngress(),
         SwitchIngressDeparser(),
         SwitchEgressParser(),
         SwitchEgress(),
         SwitchEgressDeparser()) pipe;

Switch(pipe) main;
