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
        self.puerto_fijo={"00:00:00:00:00:01":1, "00:00:00:00:00:02":2,
                  "00:00:00:00:00:03":3, "00:00:00:00:00:04":4}



    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        msg=ev.msg
        dp=msg.datapath
        ofp=dp.ofproto
        parser=dp.ofproto_parser

        match1=parser.OFPMatch(eth_type=0x0806)

        match2=parser.OFPMatch(eth_type=0x800, ip_proto=17, udp_dst=68)

        match3=parser.OFPMatch(eth_type=0x800, ip_proto=17, udp_dst=67)

        actions=[parser.OFPActionOutput(ofp.OFPP_CONTROLLER, ofp.OFPCML_NO_BUFFER)]
        inst=[parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
        mod1=parser.OFPFlowMod(datapath=dp, table_id=0, priority=100, match=match1, instructions=inst)
        mod2=parser.OFPFlowMod(datapath=dp, table_id=0, priority=100, match=match2, instructions=inst)
       
        gototable1=parser.OFPInstructionGotoTable(1) 
        inst3=[parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions), gototable1]
        mod3=parser.OFPFlowMod(datapath=dp, table_id=0, priority=100, match=match3, instructions=inst3)

        dp.send_msg(mod1)
        dp.send_msg(mod2)
        dp.send_msg(mod3)

        match4=parser.OFPMatch()
        mod4=parser.OFPFlowMod(datapath=dp, table_id=0, priority=0, match=match4, instructions=[gototable1])
        dp.send_msg(mod4)

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

        # 1. mensaje del cliente (Discover, Request): solo anotar su puerto
        if dhcpO.op==1:
            self.mac_puerto[dhcpO.chaddr]=in_port         # libreta A
            self.logger.info("Cliente %s en el puerto %s", dhcpO.chaddr, in_port)
            return                                        # el original ya siguio a la tabla 1

        # 2. mensaje de servidor por un puerto no confiable: bloquear
        if in_port!=puerto_confiable:
            self.logger.warning("Llego un dhcp del puerto %s que no corresponde al servidor, bloqueandolo...", in_port)
            match=parser.OFPMatch(in_port=in_port)
            inst=[parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, [])]
            mod=parser.OFPFlowMod(datapath=dp, table_id=0, priority=200, match=match, instructions=inst)
            dp.send_msg(mod)
            return

        # 3. viene del servidor (Offer, ACK o NAK): buscar el puerto del cliente
        mac_cliente=dhcpO.chaddr
        if mac_cliente in self.mac_puerto:
            puerto_salida=self.mac_puerto[mac_cliente]
        else:
            puerto_salida=ofp.OFPP_FLOOD

        # 4. solo el ACK crea el binding: IP -> (MAC, puerto)
        if self.tipo_dhcp(dhcpO)==5 and mac_cliente in self.mac_puerto:
            ip_asignada=dhcpO.yiaddr
            self.tabla_verdad[ip_asignada]=(mac_cliente, puerto_salida)
            self.logger.info("Aprendiendo que la mac %s en el puerto %s va a tener la ip %s", mac_cliente, puerto_salida, ip_asignada)

        # 5. reenviar directo al cliente (Offer, ACK y NAK)
        actions=[parser.OFPActionOutput(puerto_salida)]
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

        # 0. puerto confiable (servidor DHCP): no se revisa, igual que P4 y Cisco
        if puerto_entrada==puerto_confiable:
            self.logger.info("ARP del puerto confiable, no se revisa")
            self.reenviar(dp, msg, puerto_entrada, mac_destino)
            return

        # 1. MAC de Ethernet distinta de la del ARP
        if eth_mac!=mac_origen:
            self.logger.warning("Paquete sospechoso, bloqueando puerto %s", puerto_entrada)
            match=parser.OFPMatch(in_port=puerto_entrada)
            inst=[parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, [])]
            mod=parser.OFPFlowMod(datapath=dp, table_id=0, priority=200, match=match, instructions=inst)
            dp.send_msg(mod)
            return

        # 2. IP con binding: comparar MAC y puerto
        if ip_envia in self.tabla_verdad:
            mac_real, puerto_real=self.tabla_verdad[ip_envia]

            if mac_real!=mac_origen or puerto_entrada!=puerto_real:
                self.logger.warning("ataque ARP detectado, bloqueando el puerto %s", puerto_entrada)
                match=parser.OFPMatch(in_port=puerto_entrada)
                inst=[parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, [])]
                mod=parser.OFPFlowMod(datapath=dp, table_id=0, priority=200, match=match, instructions=inst)
                dp.send_msg(mod)
                return

            self.logger.info("Es un arp sano, la mac %s corresponde con la mac registrada de la tabla dhcp.....", mac_origen)
            self.reenviar(dp, msg, puerto_entrada, mac_destino)
            return

        # 3. IP sin binding
        if ip_envia not in ["0.0.0.0", "255.255.255.255"]:
            self.logger.warning("Es un ataque, el atacante esta usando ip estatica")
            match=parser.OFPMatch(in_port=puerto_entrada)
            inst=[parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, [])]
            mod=parser.OFPFlowMod(datapath=dp, table_id=0, priority=200, match=match, instructions=inst)
            dp.send_msg(mod)
        else:
            self.logger.info("Es un arp probe, dejemoslo pasar")
            self.reenviar(dp, msg, puerto_entrada, mac_destino)


    def reenviar(self, dp, msg, puerto_entrada, mac_destino):
        ofp=dp.ofproto
        parser=dp.ofproto_parser

        if mac_destino in self.puerto_fijo:
            puerto_salida=self.puerto_fijo[mac_destino]      # unicast a un host conocido
        else:
            puerto_salida=ofp.OFPP_FLOOD                      # broadcast (o MAC desconocida)

        actions=[parser.OFPActionOutput(puerto_salida)]
        out=parser.OFPPacketOut(datapath=dp, buffer_id=ofp.OFP_NO_BUFFER,
                                in_port=puerto_entrada, actions=actions, data=msg.data)
        dp.send_msg(out)



            
