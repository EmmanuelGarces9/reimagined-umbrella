from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ether_types, ethernet, arp, dhcp, udp

puerto_confiable=1

class mitigacionDhcp(app_manager.RyuApp):
    OFP_VERSIONS=[ofproto_v1_3.OFP_VERSION]

    def __init__(self, *_args, **_kwargs):
        super(mitigacionDhcp,self).__init__(*_args, **_kwargs)
        self.tabla_verdad={}
        self.mac_puerto={}




    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        msg=ev.msg
        dp=msg.datapath
        ofp=dp.ofproto
        parser=dp.ofproto_parser

        match1=parser.OFPMatch(eth_type=0x0806)

        match2=parser.OFPMatch(eth_type=0x800, ip_proto=17, udp_dst=68)

        actions=[parser.OFPActionOutput(ofp.OFPP_CONTROLLER, ofp.OFPCML_NO_BUFFER)]
        inst=[parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
        mod1=parser.OFPFlowMod(datapath=dp, table_id=0, priority=100, match=match1, instructions=inst)
        mod2=parser.OFPFlowMod(datapath=dp, table_id=0, priority=100, match=match2, instructions=inst)
        dp.send_msg(mod1)
        dp.send_msg(mod2)

        gototable1=parser.OFPInstructionGotoTable(1)
        match3=parser.OFPMatch()
        mod3=parser.OFPFlowMod(datapath=dp, table_id=0, priority=0, match=match3, instructions=[gototable1])
        dp.send_msg(mod3)

        self.logger.info("Switch conectado, instalando reglas ARP")

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self,ev):
        msg=ev.msg
        if msg.table_id != 0:
            return
        dp=msg.datapath
        ofp=dp.ofproto
        parser=dp.ofproto_parser

        pkt = packet.Packet(msg.data)
        ethO = pkt.get_protocol(ethernet.ethernet)
        arpO = pkt.get_protocol(arp.arp)
        dhcpO = pkt.get_protocol(dhcp.dhcp)
        puerto_entrada=msg.match['in_port']

        if arpO:
            self.comprobarArp(ev, arpO, ethO)
        elif dhcpO:
            self.dhcpsnoop(ev, dhcpO, puerto_entrada)
        else:
            return

    def dhcpsnoop(self, ev, dhcpO, in_port):
        msg=ev.msg
        dp=msg.datapath
        ofp=dp.ofproto
        parser=dp.ofproto_parser

        if self.tipo_dhcp(dhcpO)==5:
            if in_port==puerto_confiable:

                mac_cliente=dhcpO.chaddr
                ip_asignada=dhcpO.yiaddr
                self.tabla_verdad[ip_asignada]=mac_cliente
                self.logger.info("Aprendiendo que la mac %s va a tener la ip %s", mac_cliente, ip_asignada)
                if mac_cliente in self.mac_puerto:
                    puerto_salida=self.mac_puerto[mac_cliente]
                else:
                    puerto_salida=ofp.OFPP_FLOOD
                actions=[parser.OFPActionOutput(puerto_salida)]
                out=parser.OFPPacketOut(datapath=dp, buffer_id=ofp.OFP_NO_BUFFER, in_port=in_port, actions=actions, data=msg.data)
                dp.send_msg(out)
            else:
                self.logger.warning("Llego un dhcp del puerto %s que no corresponde al servidor, bloqueandolo...", in_port)
                match=parser.OFPMatch(in_port=in_port)
                inst=[parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, [])]
                mod=parser.OFPFlowMod(datapath=dp, table_id=0, priority=200, match=match, instructions=inst)
                dp.send_msg(mod)
        else:
            self.logger.info("Son paquetes DHCP offer, NAK, se dejan pasar sin problema........")
            # Offer, NAK, etc: reenviar sin procesar
            actions=[parser.OFPActionOutput(ofp.OFPP_FLOOD)]
            out=parser.OFPPacketOut(datapath=dp, buffer_id=ofp.OFP_NO_BUFFER, in_port=in_port, actions=actions, data=msg.data)
            dp.send_msg(out)



    def tipo_dhcp(self, dhcpObj):
        for opcion in dhcpObj.options.option_list:
            if opcion.tag == 53:
                return opcion.value[0]
        return None

    def comprobarArp(self, ev, arpO, ethO):
        msg=ev.msg
        dp=msg.datapath
        ofp=dp.ofproto
        parser=dp.ofproto_parser
        eth_mac=ethO.src
        mac_origen=arpO.src_mac
        mac_destino=ethO.dst
        ip_envia=arpO.src_ip
        puerto_entrada=msg.match['in_port']   
        ip_destino=arpO.dst_ip

        if eth_mac!=mac_origen:
            self.logger.warning("Paquete sospechoso, bloqueando puerto %s", puerto_entrada)
            match=parser.OFPMatch(in_port=puerto_entrada)
            actions=[]
            inst=[parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
            mod=parser.OFPFlowMod(datapath=dp, table_id=0, priority=200, match=match, instructions=inst)
            dp.send_msg(mod)
            return
        if ip_envia in self.tabla_verdad:
            mac_real=self.tabla_verdad[ip_envia]

            if mac_real!=mac_origen:
                self.logger.warning("ataque ARP detectado, bloqueando el puerto %s", puerto_entrada)
                match=parser.OFPMatch(in_port=puerto_entrada)
                inst=[parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, [])]
                mod=parser.OFPFlowMod(datapath=dp, table_id=0, priority=200, match=match, instructions=inst)
                dp.send_msg(mod)
                return
            self.logger.info("Es un arp sano, la mac %s corresponde con la mac registrada de la tabla dhcp.....", mac_origen)
            if mac_destino in self.mac_puerto:
                puerto_salida=self.mac_puerto[mac_destino]
            else:
                puerto_salida=ofp.OFPP_FLOOD
            actions=[parser.OFPActionOutput(puerto_salida)]
            out=parser.OFPPacketOut(datapath=dp, buffer_id=ofp.OFP_NO_BUFFER, in_port=puerto_entrada, actions=actions, data=msg.data)
            dp.send_msg(out)
            return
        else:
            if puerto_entrada==puerto_confiable:
                if mac_destino in self.mac_puerto:
                    puerto_salida=self.mac_puerto[mac_destino]
                else:
                    puerto_salida=ofp.OFPP_FLOOD
                actions=[parser.OFPActionOutput(puerto_salida)]
                out=parser.OFPPacketOut(datapath=dp, buffer_id=ofp.OFP_NO_BUFFER, in_port=puerto_entrada, actions=actions, data=msg.data)
                dp.send_msg(out)
                self.logger.info("El servidor dhcp esta mandando paquetes arp, son sanos")
                return
            else:
                if ip_envia not in ["0.0.0.0", "255.255.255.255"]:
                    self.logger.warning("Es un ataque, el atacante esta usando ip estatica")
                    match=parser.OFPMatch(in_port=puerto_entrada)
                    inst=[parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, [])]
                    mod=parser.OFPFlowMod(datapath=dp, table_id=0, priority=200, match=match, instructions=inst)
                    dp.send_msg(mod)
                else:
                    self.logger.info("Es un arp probe, dejemoslo pasar")
                    if mac_destino in self.mac_puerto:
                        puerto_salida=self.mac_puerto[mac_destino]
                    else:
                        puerto_salida=ofp.OFPP_FLOOD
                    actions=[parser.OFPActionOutput(puerto_salida)]
                    out=parser.OFPPacketOut(datapath=dp, buffer_id=ofp.OFP_NO_BUFFER, in_port=puerto_entrada, actions=actions, data=msg.data)
                    dp.send_msg(out)
                return




            