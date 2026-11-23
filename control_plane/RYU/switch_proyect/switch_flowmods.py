from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, set_ev_cls, CONFIG_DISPATCHER
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet

class switch_flowmod(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(switch_flowmod, self).__init__(*args, **kwargs)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        msg=ev.msg
        dp=msg.datapath
        ofp=dp.ofproto
        parser=dp.ofproto_parser

        
        hosts=[
            {"ip" : "10.0.0.1", "mac" : "00:00:00:00:00:01", "port":1},
            {"ip" : "10.0.0.2", "mac" : "00:00:00:00:00:02", "port":2},
            {"ip" : "10.0.0.3", "mac" : "00:00:00:00:00:03", "port":3},
            {"ip" : "10.0.0.4", "mac" : "00:00:00:00:00:04", "port":4},
        ]
        for host in hosts:

            match=parser.OFPMatch(eth_dst=host["mac"])
            actions=[parser.OFPActionOutput(host["port"])]
            inst=[parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
            mod=parser.OFPFlowMod(datapath=dp, table_id=1, priority=1, match=match, instructions=inst)
            dp.send_msg(mod)
        

        match=parser.OFPMatch(eth_dst="ff:ff:ff:ff:ff:ff")
        actions=[parser.OFPActionOutput(ofp.OFPP_FLOOD)]
        inst=[parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
        mod=parser.OFPFlowMod(datapath=dp, table_id=1, priority=1, match=match, instructions=inst)
        dp.send_msg(mod)


        self.logger.info("Switch %s conectado, instalando reglas", dp.id)
   
