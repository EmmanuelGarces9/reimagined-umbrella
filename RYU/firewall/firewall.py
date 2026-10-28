from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet


class firewall(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(firewall, self).__init__(*args, **kwargs)
        self.mac_to_port = {}

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        msg=ev.msg
        dp=msg.datapath
        ofp=dp.ofproto
        parser=dp.ofproto_parser
        
        
        with open('firewall-policies.csv', 'r') as firefile:
            for linea in firefile:
                if linea.startswith('id'):
                    continue
                datos=linea.strip().split(',')
                if len(datos)==3:
                    mac1=datos[1]
                    mac2=datos[2]
                    match1=parser.OFPMatch(eth_src=mac1, eth_dst=mac2)
                    match2=parser.OFPMatch(eth_src=mac2, eth_dst=mac1)
                    actions=[]
                    inst1=[parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
                    inst2=[parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
                    mod1=parser.OFPFlowMod(datapath=dp, priority=200, match=match1, instructions=inst1)
                    mod2=parser.OFPFlowMod(datapath=dp, priority=200, match=match2, instructions=inst2)
                    dp.send_msg(mod1)
                    dp.send_msg(mod2)
                    self.logger.info("Regla de firewall #%s instalada: %s <-> %s", datos[0], mac1, mac2)

