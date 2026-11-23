#include <core.p4>
#include <v1model.p4>

typedef bit<9> portType_t;
typedef bit<1> valid_t;
typedef bit<32> indexP4_t;
typedef bit<48> time_t;
typedef bit<32> count_t;

const bit<16> IPV4=0x800;
const bit<16> ARP=0x806;
const bit<48> bcast = 0xFFFFFFFFFFFF; 
const time_t REQ_W = 1000000; //measured in us
const count_t REQ_TH = 10;
const time_t REP_W = 15000000; //measured in us
//const bit<> REP_W = 30000000; //measured in us
const count_t REP_TH = 6; //measured in units
//const bit<> REP_TH = 10; //measured in units
const bit<9> SERVER_PORT = 1;

header ethernet_t {
    bit<48> dstAddr;
    bit<48> srcAddr;
    bit<16> etherType;
}
header arp_t{
    bit<16> htype;  //hardware type, usually it is ethertnet =1
    bit<16> ptype;  // protocol type, it is 0x800
    bit<8> hlen;  //hardware length, it means MAC length: 6 bytes
    bit<8> plen;  // ip length
    bit<16> oper;  //operation: arp type: 1 req, 2 reply
    bit<48> sha;  // sender hardware address: MAC of host sending
    bit<32> spa;  // sender protocol address: IP of host sending
    bit<48> tha;  // target hardware address: MAC of host receiving
    bit<32> tpa;  //target protocol address: IP of host receiving
}
header ipv4_t{
    bit<4> version; //if its ipv4 the 4 bits are num 4, if its ipv6 the 4 bits are num 6
    bit<4> hlen;  //header length: h3 header length, usually 5
    bit<8> tos; //type of service: tipo de servicio, implements quality policies of service
    bit<16> totalen; //total length: total length of ip packet: h3+data
    bit<16> ID; // identification: it is useful when an original packet was fragmented
    bit<3> flags; //flags: they indicate if the packet is a fragment and if its the last fragment
    bit<13> fragOff; // fragment offset: indicates the position of the fragment in the original packet
    bit<8> ttl; // time to live: control number made to limit the life of a packet 
    bit<8> protocol; //protocol: indicates the protocol of the packet: icmp 1, TCP 6, UDP 17, etc
    bit<16> hdrCheck; // header checksum: value of checksum of h3 header
    bit<32> srcIpAddr; //source ip address: ip of host sending
    bit<32> dstIpAddr; //destination ip address: ip of host receiving
}

struct metadata {

}

struct headers{
    ethernet_t eth;
    ipv4_t ipv4;
    arp_t arp;
}


parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata){
            
    state start{
        packet.extract(hdr.eth);
        transition select(hdr.eth.etherType){
            IPV4: parse_ipv4;
            ARP: parse_arp;
            default: accept;
        }

    }
    state parse_ipv4{
        packet.extract(hdr.ipv4);
        transition accept;
    }
    state parse_arp{
        packet.extract(hdr.arp);
        transition accept;
    }

}

control MyVerifyChecksum(inout headers hdr, inout metadata meta){
    apply{ }
}

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata){

    register<count_t>(512) reg_req_count;      // request counter register
    register<time_t>(512) reg_req_tstart;       // request time register
    register<count_t>(512) reg_rep_count;     // replies counter register
    register<time_t>(512) reg_rep_tstart; //replies time register
    register<valid_t>(512) reg_blocked;  // ports blocked register


    action drop(){
        mark_to_drop(standard_metadata);
    }

    action forward(portType_t port){
        standard_metadata.egress_spec=port;
    }

   
    table mac_forw{
        key={
            hdr.eth.dstAddr: exact;
        }
        actions={
            forward;
            drop;
            NoAction;
        }
        size=1024;
        default_action=drop();
    }
    
    apply {
        // in port as index to look in reg_blocked
        indexP4_t index_p = (bit<32>) standard_metadata.ingress_port; //maps a 9 bits port to 32 bits port
        valid_t port_blocked;
        reg_blocked.read(port_blocked, index_p);

        bool discard = false;

        // 1. is it a blocked port? then block
        if (port_blocked == 1) {
            discard = true;
        }

        else if (hdr.arp.isValid() && standard_metadata.ingress_port != SERVER_PORT) {
            time_t actual_t = standard_metadata.ingress_global_timestamp;
            
            if (hdr.arp.oper==1){
                time_t tstart;
                count_t cntr;
                reg_req_tstart.read(tstart, index_p);
                reg_req_count.read(cntr, index_p);

                if (actual_t - tstart > REQ_W){
                    tstart=actual_t;
                    cntr=1;
                    reg_req_tstart.write(index_p, tstart);
                }
                else{
                    cntr = cntr+1;
                }
                reg_req_count.write(index_p, cntr);
                if (cntr>REQ_TH){
                    discard=true;
                    reg_blocked.write(index_p, 1);
                }
            
            }
            else if (hdr.arp.oper == 2){
                time_t tstart;
                count_t cntr;
                reg_rep_tstart.read(tstart, index_p);
                reg_rep_count.read(cntr, index_p);

                if (actual_t - tstart > REP_W){
                    tstart=actual_t;
                    cntr=1;
                    reg_rep_tstart.write(index_p, tstart);
                }
                else{
                    cntr = cntr+1;
                }
                reg_rep_count.write(index_p, cntr);
                if (cntr>REP_TH){
                    discard=true;
                    reg_blocked.write(index_p, 1);
                }
                
            }
        }
        
        // final decision
        if (discard) {
            drop();
        }
        else if (hdr.eth.dstAddr==bcast) {
            standard_metadata.mcast_grp=1;
        }
        else {
            mac_forw.apply();
        }
    }

}

control MyEgress(inout headers hdr, inout metadata meta,
                 inout standard_metadata_t standard_metadata) { 
    apply { 
        if (standard_metadata.egress_port==standard_metadata.ingress_port){
            mark_to_drop(standard_metadata);

        }
    } 
}

control MyComputeChecksum(inout headers hdr, inout metadata meta){

    apply { }

}

control MyDeparser(packet_out packet, in headers hdr){
    apply{

    packet.emit(hdr.eth);
    packet.emit(hdr.arp);
    packet.emit(hdr.ipv4);
    }
}


V1Switch(
    MyParser(),
    MyVerifyChecksum(),
    MyIngress(),
    MyEgress(),
    MyComputeChecksum(),
    MyDeparser()
) main;



