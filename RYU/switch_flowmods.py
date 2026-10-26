from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, set_ev_cls, CONFIG_DISPATCHER
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet

class switch_flowmod(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(switch_flowmod, self).__init__(*args, **kwargs)
        self.mac_puerto = {}

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        msg=ev.msg
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

        puerto_entrada=msg.match['in_port']
        pkt=packet.Packet(msg.data)
        eth=pkt.get_protocol(ethernet.ethernet)
        mac_origen=eth.src
        mac_destino=eth.dst

        if mac_destino in self.mac_puerto:
            puerto_salida=self.mac_puerto[mac_destino]
            self.logger.info("enviando paquete de %s a %s por el puerto %s", mac_origen, mac_destino, puerto_salida)
            actions=[parser.OFPActionOutput(puerto_salida)]

            match=parser.OFPMatch(in_port=puerto_entrada, eth_dst=mac_destino, eth_src=mac_origen)
            inst=[parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
            mod=parser.OFPFlowMod(datapath=dp, priority=1, match=match, instructions=inst)
            dp.send_msg(mod)

        else:
            self.logger.info("inundando paquete de %s a %s", mac_origen, mac_destino)
            actions=[parser.OFPActionOutput(ofp.OFPP_FLOOD)]
            out=parser.OFPPacketOut(datapath=dp, buffer_id=ofp.OFP_NO_BUFFER, in_port=puerto_entrada, actions=actions, data=msg.data)
            dp.send_msg(out)


        if mac_origen not in self.mac_puerto:
            self.logger.info("aprendiendo la ubicación de %s en el puerto %s", mac_origen, puerto_entrada)
            self.mac_puerto[mac_origen]=puerto_entrada