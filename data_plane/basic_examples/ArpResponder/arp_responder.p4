#include <core.p4>
#include <v1model.p4>

typedef bit<9> portType_t;
typedef bit<48> macType_t;
typedef bit<32> ipType_t;

const bit<16> IPV4=0x800;
const bit<16> ARP=0x806;



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

    action drop(){
        mark_to_drop(standard_metadata);
    }

    action forward(portType_t port){
        standard_metadata.egress_spec=port;
    }

    action resolve_arp(macType_t asked_mac){
        macType_t who_asked_l2=hdr.arp.sha;
        ipType_t who_asked_l3=hdr.arp.spa;
        ipType_t asked_ip=hdr.arp.tpa;

        hdr.arp.oper=2;
        
        hdr.arp.sha=asked_mac;
        hdr.arp.spa=asked_ip;

        hdr.arp.tha=who_asked_l2;
        hdr.arp.tpa=who_asked_l3;

        hdr.eth.dstAddr=who_asked_l2;
        hdr.eth.srcAddr=asked_mac;

        standard_metadata.egress_spec=standard_metadata.ingress_port;
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

    table arp_response{
        key={
            hdr.arp.tpa: exact;
        }
        actions={
            resolve_arp;
            drop;
            NoAction;
        }
        size=1024;
        default_action=drop();
    }
    
    apply{
        
        if (hdr.arp.isValid() && hdr.arp.sha != hdr.eth.srcAddr){
            drop();
        }

        
        else if (hdr.arp.isValid() && hdr.arp.oper==1){
            arp_response.apply(); 
        }
        else{
            mac_forw.apply();
        }
    }
}

control MyEgress(inout headers hdr, inout metadata meta,
                 inout standard_metadata_t standard_metadata) { 
    apply { } 
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











