from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, arp, ether_types


mac_controlador="00:00:00:0a:00:00"
ip_controlador="10.0.0.250"

class basicmitigation(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(basicmitigation, self).__init__(*args, **kwargs)
        self.tabla_verdad={}
        self.mac_puerto={}
        self.pendientes={}


    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        msg=ev.msg
        dp=msg.datapath
        ofp=dp.ofproto
        parser=dp.ofproto_parser
        
        match=parser.OFPMatch(eth_type=0x0806)


        actions=[parser.OFPActionOutput(ofp.OFPP_CONTROLLER, ofp.OFPCML_NO_BUFFER)]
        inst=[parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
        mod=parser.OFPFlowMod(datapath=dp, table_id=0, priority=10, match=match, instructions=inst)
        dp.send_msg(mod)

        gototable1=parser.OFPInstructionGotoTable(1)
        match2=parser.OFPMatch()
        mod2=parser.OFPFlowMod(datapath=dp, table_id=0, priority=0, match=match2, instructions=[gototable1])
        dp.send_msg(mod2)

        self.logger.info("Switch conectado, instalando reglas de ARP")

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg=ev.msg
        if msg.table_id!=0:
            return
        dp=msg.datapath
        ofp=dp.ofproto
        parser=dp.ofproto_parser

        pkt=packet.Packet(msg.data)
        ethO=pkt.get_protocol(ethernet.ethernet)
        arpO=pkt.get_protocol(arp.arp)
        if arpO is None or ethO is None:
            return
        eth_mac=ethO.src
        mac_origen=arpO.src_mac
        mac_destino=ethO.dst
        ip_envia=arpO.src_ip
        puerto_entrada=msg.match['in_port']   
        ip_destino=arpO.dst_ip

        if ip_destino==ip_controlador and ip_envia not in self.pendientes: return

        
        if ip_envia in self.pendientes:
            mac_pendiente, puerto_pendiente, data_pendiente=self.pendientes[ip_envia]
            if ip_destino==ip_controlador:
                if mac_origen==mac_pendiente:
                    self.logger.info("Verificacion exitosa: %s es realmente %s", ip_envia, mac_origen)
                    self.mac_puerto[mac_origen]=puerto_entrada
                    self.tabla_verdad[ip_envia]=mac_origen
                    del self.pendientes[ip_envia]
                    if data_pendiente is not None:
                        if mac_destino in self.mac_puerto:
                            puerto_salida=self.mac_puerto[mac_destino]
                        else:
                            puerto_salida=ofp.OFPP_FLOOD
                        actions=[parser.OFPActionOutput(puerto_salida)]
                        out=parser.OFPPacketOut(datapath=dp, buffer_id=ofp.OFP_NO_BUFFER, in_port=puerto_pendiente, actions=actions, data=data_pendiente)
                        dp.send_msg(out)
                else:
                    self.logger.warning("Verificacion fallida: %s decia ser %s (puerto %s), el real es %s (puerto %s)", ip_envia, mac_pendiente, puerto_pendiente, mac_origen, puerto_entrada)
                    match=parser.OFPMatch(in_port=puerto_pendiente)
                    inst=[parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, [])]
                    mod=parser.OFPFlowMod(datapath=dp, table_id=0, priority=20, match=match, instructions=inst)
                    dp.send_msg(mod)
                    del self.pendientes[ip_envia]                
                return 

            else:
                if arpO.opcode==arp.ARP_REPLY:
                    self.logger.warning("Es un intento de ataque, no ha pasado la verificacion, bloqueando puerto %s", puerto_entrada)
                    match=parser.OFPMatch(in_port=puerto_entrada)
                    actions=[]
                    inst=[parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)] 
                    mod=parser.OFPFlowMod(datapath=dp, table_id=0, priority=20, match=match, instructions=inst) 
                    dp.send_msg(mod)   
                    del self.pendientes[ip_envia]                                   
                else:
                    if data_pendiente is not None:
                        self.logger.info("Es un arp request, lo dejamos pasar")
                        if mac_destino in self.mac_puerto:
                            puerto_salida=self.mac_puerto[mac_destino]
                        else:
                            puerto_salida=ofp.OFPP_FLOOD
                        actions=[parser.OFPActionOutput(puerto_salida)]
                        out=parser.OFPPacketOut(datapath=dp, buffer_id=ofp.OFP_NO_BUFFER, in_port=puerto_entrada, actions=actions, data=data_pendiente)
                        dp.send_msg(out)
                return
        if eth_mac!=mac_origen:
            self.logger.warning("Paquete sospechoso, bloqueando puerto %s", puerto_entrada)
            match=parser.OFPMatch(in_port=puerto_entrada)
            actions=[]
            inst=[parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
            mod=parser.OFPFlowMod(datapath=dp, table_id=0, priority=20, match=match, instructions=inst)
            dp.send_msg(mod)
            return

        if ip_envia in self.tabla_verdad:
            mac_verdadera=self.tabla_verdad[ip_envia]
            if mac_verdadera!=mac_origen:
                self.logger.warning("ARP spoofing detectado: la mac %s intenta suplantar a la mac %s para la ip %s", mac_origen, mac_verdadera, ip_envia)
                
                match=parser.OFPMatch(in_port=puerto_entrada)
                actions=[]
                inst=[parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
                mod=parser.OFPFlowMod(datapath=dp, table_id=0, priority=20, match=match, instructions=inst)
                dp.send_msg(mod)
                return
            else:
                if mac_destino in self.mac_puerto:
                    puerto_salida=self.mac_puerto[mac_destino]
                else:
                    puerto_salida=ofp.OFPP_FLOOD
                actions=[parser.OFPActionOutput(puerto_salida)]
                out=parser.OFPPacketOut(datapath=dp, buffer_id=ofp.OFP_NO_BUFFER, in_port=puerto_entrada, actions=actions, data=msg.data)
                dp.send_msg(out)
                self.logger.info("fue un arp legitimo, enviando paquete de %s a %s por el puerto %s", mac_origen, mac_destino, puerto_salida)
        else:
            data_pendiente=msg.data
            if arpO.opcode==arp.ARP_REQUEST:
                data_pendiente=None
            self.pendientes[ip_envia]=(mac_origen, puerto_entrada, data_pendiente)
            self.logger.info("Ip %s no registrada, enviando verificacion al puerto %s", ip_envia, puerto_entrada)
            self.enviar_verificacion(ev, ip_envia)

            if arpO.opcode==arp.ARP_REQUEST:
                self.logger.info("Es un paquete ARP request de %s para %s, dejemoslo pasar para que no muera la red, pero igual se verificara", ip_envia, arpO.dst_ip)
                if mac_destino in self.mac_puerto:
                    puerto_salida=self.mac_puerto[mac_destino]
                else:
                    puerto_salida=ofp.OFPP_FLOOD
                actions=[parser.OFPActionOutput(puerto_salida)]
                out=parser.OFPPacketOut(datapath=dp, buffer_id=ofp.OFP_NO_BUFFER, in_port=puerto_entrada, actions=actions, data=msg.data)
                dp.send_msg(out)


    def enviar_verificacion(self, ev, ip_envia):
        msg=ev.msg
        dp=msg.datapath
        ofp=dp.ofproto
        parser=dp.ofproto_parser

        pkt=packet.Packet()
        pkt.add_protocol(ethernet.ethernet(ethertype=ether_types.ETH_TYPE_ARP, src=mac_controlador, dst='ff:ff:ff:ff:ff:ff'))
        pkt.add_protocol(arp.arp(opcode=arp.ARP_REQUEST, src_mac=mac_controlador, src_ip=ip_controlador, dst_mac='00:00:00:00:00:00', dst_ip=ip_envia))
        pkt.serialize()
        actions=[parser.OFPActionOutput(ofp.OFPP_FLOOD)]
        out=parser.OFPPacketOut(datapath=dp, buffer_id=ofp.OFP_NO_BUFFER, in_port=ofp.OFPP_CONTROLLER, actions=actions, data=pkt.data)
        dp.send_msg(out)


