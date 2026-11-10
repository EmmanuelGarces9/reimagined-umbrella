from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet


class myswitch(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(myswitch, self).__init__(*args, **kwargs)
        self.mac_puerto = {}

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        msg = ev.msg
        dp=msg.datapath
        ofp=dp.ofproto
        parser=dp.ofproto_parser
        match=parser.OFPMatch()
        actions=[parser.OFPActionOutput(ofp.OFPP_CONTROLLER, ofp.OFPCML_NO_BUFFER)]
        inst=[parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
        mod=parser.OFPFlowMod(datapath=dp, priority=0, match=match, instructions=inst)
        dp.send_msg(mod)
        self.logger.info("Switch %s conectado, instalando reglas", dp.id)


    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg=ev.msg
        dp=msg.datapath
        ofp=dp.ofproto
        parser=dp.ofproto_parser
        #agregar al diccionario el puerto y la mac
        pkt=packet.Packet(msg.data)
        eth=pkt.get_protocol(ethernet.ethernet)
        mac_origen=eth.src
        mac_destino=eth.dst
        puerto_entrada=msg.match['in_port']

        if mac_destino in self.mac_puerto:
            self.logger.info("Switch %s: enviando paquete de %s a %s", dp.id, mac_origen, mac_destino)
            puerto_salida=self.mac_puerto[mac_destino]
            actions=[parser.OFPActionOutput(puerto_salida)]
            out=parser.OFPPacketOut(datapath=dp, buffer_id=ofp.OFP_NO_BUFFER, in_port=puerto_entrada, actions=actions, data=msg.data)
            dp.send_msg(out)


        else:
            self.logger.info("Switch %s: inundando paquete de %s a %s", dp.id, mac_origen, mac_destino)
            actions=[parser.OFPActionOutput(ofp.OFPP_FLOOD)]
            out=parser.OFPPacketOut(datapath=dp, buffer_id=ofp.OFP_NO_BUFFER, in_port=puerto_entrada, actions=actions, data=msg.data)
            dp.send_msg(out)
        
        if mac_origen not in self.mac_puerto: 
            self.logger.info("Switch %s: aprendiendo la ubicación de %s en el puerto %s", dp.id, mac_origen, puerto_entrada)
            self.mac_puerto[mac_origen]=puerto_entrada