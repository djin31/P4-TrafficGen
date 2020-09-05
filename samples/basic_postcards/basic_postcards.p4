/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

#define CLONE_SESSION_ID 99
#define COLLECTOR_PORT_ID 3
#define CLONE_INSTANCE 1

const bit<16> TYPE_IPV4 = 0x800;
const bit<8>  TYPE_UDP = 0x11;
const bit<48> MAC_H1 = 0x00aabb000001;
const bit<48> MAC_H2 = 0x00aabb000002;
const bit<48> MAC_H3 = 0x00aabb000003;
const bit<48> SWITCH_MAC = 0xaabbccddeeff;
const bit<32> SWITCH_IP = 0xc0a80163;  // 192.168.1.99
const bit<32> COLLECTOR_IP = 0x0a000003;
const bit<16> SWITCH_UDP_PORT = 16w1818;
const bit<16> COLLECTOR_UDP_PORT = 16w9999;

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

header ethernet_t {  // 14 bytes
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

header udp_t {
    bit<16> src_port;
    bit<16> dst_port;
    bit<16> len;
    bit<16> checksum;
}

header header_metadata_t {  // 21 bytes
    macAddr_t mac_dstAddr;
    macAddr_t mac_srcAddr;
    ip4Addr_t ip_srcAddr;
    ip4Addr_t ip_dstAddr;
    bit<8>    ip_protocol;
}

header queueing_metadata_t { // 14 bytes
    bit<24> enq_qdepth;
    bit<24> deq_qdepth;
    bit<32> deq_timedelta;
    bit<32> enq_timestamp;
}

struct metadata {
    bit<32> cloning_session;
}

struct headers {
    ethernet_t   ethernet;
    ipv4_t       ipv4;
    udp_t        udp;
    header_metadata_t hdr_meta;
    queueing_metadata_t q_meta;
}

error { IPv4BadHeader }

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser ParserImpl(packet_in packet,
                  out headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {

    
    state start {
	/* TODO: add transition to parsing ethernet */
        transition parse_ethernet;
    }

    state parse_ethernet {
	/* TODO: add parsing ethernet */
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType){
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
	/* TODO: add parsing ipv4 */
        packet.extract(hdr.ipv4);
        verify(hdr.ipv4.version == 4, error.IPv4BadHeader);
        verify(hdr.ipv4.ihl >= 5, error.IPv4BadHeader);
        transition select(hdr.ipv4.protocol){
            TYPE_UDP: parse_udp;
            default: accept;
        }
    }

    state parse_udp {
        packet.extract(hdr.udp);
        transition select(hdr.udp.dst_port){
            COLLECTOR_UDP_PORT: parse_hdr_meta;
            default: accept;
        }
    }

    state parse_hdr_meta {
        packet.extract(hdr.hdr_meta);
        transition select(hdr.hdr_meta.ip_protocol){
            default:transition parse_q_meta;
        }
    }

    state parse_q_meta {
        packet.extract(hdr.q_meta);
        transition accept;
    }
}


/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control verifyChecksum(inout headers hdr, inout metadata meta) 
{ apply { } }


/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control ingress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {

    /* This action will drop packets */
    action drop() {
        mark_to_drop();
    }
    
    action forward(egressSpec_t port) {

        standard_metadata.egress_spec = port;
        // digest<bit<32>>(32w0, standard_metadata.packet_length);
    }
    
    table mac_forward {
        
        key = {
            hdr.ethernet.dstAddr: exact;
        }

        actions = {
            forward;
            drop;
        }

        // Static entries. It's a L2 "learned" switch.
        const entries = {
            MAC_H1: forward(9w1);
            MAC_H2: forward(9w2);
            MAC_H3: forward(9w3);
        }
        size = 3;
        default_action = drop;
    }
    
    apply {
	   mac_forward.apply();

       if(hdr.ipv4.protocol == TYPE_UDP){ // condition for cloning
            meta.cloning_session = CLONE_SESSION_ID;
            clone3(CloneType.I2E, CLONE_SESSION_ID, meta.cloning_session);
       }
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control egress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    
    
    action add_header_metadata(){
        hdr.hdr_meta.setValid();
        hdr.hdr_meta.mac_srcAddr = hdr.ethernet.srcAddr;
        hdr.hdr_meta.mac_dstAddr = hdr.ethernet.dstAddr;
        hdr.hdr_meta.ip_srcAddr  = hdr.ipv4.srcAddr;
        hdr.hdr_meta.ip_dstAddr  = hdr.ipv4.dstAddr;
        hdr.hdr_meta.ip_protocol = hdr.ipv4.protocol;
    }


    action add_queueing_metadata(){
        hdr.q_meta.setValid();
        hdr.q_meta.enq_qdepth = (bit<24>) standard_metadata.enq_qdepth;
        hdr.q_meta.deq_qdepth = (bit<24>) standard_metadata.deq_qdepth;
        hdr.q_meta.deq_timedelta = standard_metadata.deq_timedelta;
        hdr.q_meta.enq_timestamp = standard_metadata.enq_timestamp;
    }

    action reform_the_packet(){
        hdr.ethernet.dstAddr = MAC_H3;
        hdr.ethernet.srcAddr = SWITCH_MAC;
        hdr.ipv4.srcAddr = SWITCH_IP;
        hdr.ipv4.dstAddr = COLLECTOR_IP;
        hdr.udp.src_port = SWITCH_UDP_PORT;
        hdr.udp.dst_port = COLLECTOR_UDP_PORT;

        hdr.udp.len = 43; // udpHdr(8)+hdrMeta(21)+qMeta(14)
        hdr.ipv4.totalLen = 63; //ipv4Hdr(20)+udpLen(43)

        truncate(77); // ipv4TotalLen(63)+outerEthernetHdr(14)
    }

    apply {
        
        if(standard_metadata.egress_port == 9w3){
            if(standard_metadata.instance_type == 32w1){ // should be a cloned instance
                
                if (!hdr.hdr_meta.isValid()){ // additional safety check
                    add_header_metadata();
                }

                if(!hdr.q_meta.isValid()){ // additional safety check
                    add_queueing_metadata();
                }

                reform_the_packet();
            }
            
        }
    }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control computeChecksum(
    inout headers  hdr,
    inout metadata meta)
{ apply { } }


/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control DeparserImpl(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.udp);
        packet.emit(hdr.hdr_meta);
        packet.emit(hdr.q_meta);
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

V1Switch(
ParserImpl(),
verifyChecksum(),
ingress(),
egress(),
computeChecksum(),
DeparserImpl()
) main;
