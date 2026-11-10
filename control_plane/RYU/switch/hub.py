from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3





class myhub(app_manager.RyuApp):
    ofp_version=[ofproto_v1_3.OFP_VERSION]


    #regla table-miss
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        dp=ev.msg.datapath
        ofp=dp.ofproto
        parser=dp.ofproto_parser

        match=parser.OFPMatch()
        actions=[parser.OFPActionOutput(ofp.OFPP_CONTROLLER, ofp.OFPCML_NO_BUFFER)]
        inst=[parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS,actions)]
        mod=parser.OFPFlowMod(datapath=dp, priority=0, match=match, instructions=inst)
        dp.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg=ev.msg
        dp=msg.datapath
        ofp=dp.ofproto
        parser=dp.ofproto_parser

        in_port=msg.match['in_port']
        self.logger.info(f"el paquete llego por el switch: {dp.id}, por el puerto: {in_port}, se procede a INUNDAR")
        actions=[parser.OFPActionOutput(ofp.OFPP_FLOOD)]
        pack_out=parser.OFPPacketOut(datapath=dp, buffer_id=ofp.OFP_NO_BUFFER,
                                    in_port=in_port, actions=actions, data=msg.data)
        dp.send_msg(pack_out)
        


        





















