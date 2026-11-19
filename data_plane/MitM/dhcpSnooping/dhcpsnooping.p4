#include <core.p4>
#include <v1model.p4>

typedef bit<9> portType_t;
typedef bit<48> macType_t;
typedef bit<32> ipType_t;
typedef bit<1> valid_t;
typedef bit<32> indexP4_t;
typedef bit<16> l4port_t;


const bit<16> IPV4=0x800;
const bit<16> ARP=0x806;
const bit<8> UDP=17;
const bit<9> SERVER_PORT=1;
const bit<48> bcast = 0xFFFFFFFFFFFF; 


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


header udp_t{
    l4port_t srcPort;
    l4port_t dstPort;
    bit<16> length;
    bit<16> checksum;
}

header dhcp_t {
    bit<8>   op;          // 1 = mensaje del cliente (Discover, Request), 2 = del servidor (Offer, ACK)
    bit<8>   htype;       // tipo de hardware: 1 = Ethernet
    bit<8>   hlen;        // longitud de la dirección de hardware: 6 bytes (una MAC)
    bit<8>   hops;        // saltos por relays DHCP; 0 en una red local
    bit<32>  xid;         // ID de la transacción: el mismo en los 4 mensajes de un cliente
    bit<16>  secs;        // segundos desde que el cliente empezó a pedir IP
    bit<16>  flags;       // bit más alto en 1 = el cliente pide que le respondan en broadcast
    bit<32>  ciaddr;      // IP actual del cliente (0.0.0.0 si todavía no tiene)
    bit<32>  yiaddr;      // "your IP": la IP que el servidor le asigna al cliente  ← la usas
    bit<32>  siaddr;      // IP del siguiente servidor (arranque por red); normalmente 0
    bit<32>  giaddr;      // IP del relay DHCP; 0 si no hay relay
    bit<48>  chaddr;      // MAC del cliente  ← la usas
    bit<80>  chaddr_pad;  // relleno: chaddr mide 16 bytes, la MAC solo ocupa los primeros 6
    bit<512> sname;       // nombre del servidor (64 bytes), casi siempre vacío
    bit<1024> file;       // nombre de archivo de arranque (128 bytes), casi siempre vacío
    bit<32>  cookie;      // "magic cookie": siempre 0x63825363, marca el inicio de las opciones
    bit<8>   opt_code;    // código de la primera opción: debe ser 53 (tipo de mensaje)  ← lo compruebas
    bit<8>   opt_len;     // longitud de esa opción: 1 byte
    bit<8>   msg_type;    // tipo: 1 Discover, 2 Offer, 3 Request, 5 ACK, 6 NAK  ← lo usas
}


struct metadata {

}

struct headers{
    ethernet_t eth;
    ipv4_t ipv4;
    arp_t arp;
    udp_t udp;
    dhcp_t dhcp;
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
        transition select(hdr.ipv4.protocol){
            UDP: parse_udp;
            default: accept;
        }
    }    

    state parse_udp{
        packet.extract(hdr.udp);
        transition select(hdr.udp.dstPort){
            67: parse_dhcp;
            68: parse_dhcp;
            default: accept;
        }
    }
    
    state parse_dhcp{
        packet.extract(hdr.dhcp);
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

    register<valid_t>(256)   reg_valid;      // ya se aprendio esa ip? indice=ip
    register<macType_t>(256) reg_mac;       // registro de macs reales indice=ip
    register<portType_t>(256) reg_port;     // registros de puertos reales indice=ip
    register<valid_t>(512)   reg_blocked;  // ese puerto ya esta bloqueado? indice=puerto
    register<portType_t>(256) reg_mac_port;

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
        //revisamos: esta bloqueado el puerto?
        portType_t port=standard_metadata.ingress_port;
        indexP4_t index_p = (bit<32>) standard_metadata.ingress_port;
        valid_t port_blocked;
        reg_blocked.read(port_blocked, index_p);
        
        bool server_answer_forw=false;
        bool discard=false;

        if (port_blocked==1){
            discard=true;

        }
        else if (hdr.dhcp.isValid()){
            indexP4_t index_m = (bit<32>) hdr.dhcp.chaddr[7:0];

            if (hdr.udp.dstPort==67){
                reg_mac_port.write(index_m, port);

            }
            else if (hdr.udp.dstPort==68){
                if (port==SERVER_PORT){
                    portType_t outPort;
                    reg_mac_port.read(outPort, index_m);
                    standard_metadata.egress_spec=outPort;
                    server_answer_forw=true;
                    if (hdr.dhcp.opt_code == 53 && hdr.dhcp.msg_type == 5){
                        indexP4_t index_ip = (bit<32>) hdr.dhcp.yiaddr[7:0];
                        macType_t real_mac = hdr.dhcp.chaddr;
                        reg_mac.write(index_ip, real_mac);
                        reg_port.write(index_ip, outPort);
                        reg_valid.write(index_ip, 1);
                    }
                }   
                else{
                    discard=true;
                    reg_blocked.write(index_p, 1);
                }
            }
        }
        else if (hdr.arp.isValid()){
            if (port != SERVER_PORT) {
                macType_t mac_pkt = hdr.arp.sha;

                // 2a. MAC de Ethernet distinta de la del ARP, primera mitigacion super basica
                if (hdr.eth.srcAddr != mac_pkt) {
                    discard = true;
                    reg_blocked.write(index_p, 1);
                }
                else if (hdr.arp.spa != 0) {
                    indexP4_t index = (bit<32>) hdr.arp.spa[7:0];
                    valid_t learned;
                    macType_t real_mac;
                    portType_t real_port;
                    reg_valid.read(learned, index);

                    if (learned == 0) {
                        // 2c. no aprendida: host con ip estatica, descartar
                        discard=true;
                        reg_blocked.write(index_p, 1);
                    }
                    else{
                        // 2d. aprendida: comparar MAC y puerto
                        reg_mac.read(real_mac, index);
                        reg_port.read(real_port, index);
                        if (real_mac != mac_pkt || real_port != port) {
                            discard = true;
                            reg_blocked.write(index_p, 1);
                        }
                    }
                }
            }
        }




        // 3. decisión final
        
        if (discard) {
            drop();
        }

        else if (server_answer_forw){

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
    packet.emit(hdr.udp);
    packet.emit(hdr.dhcp);
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











