from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ether_types, ethernet, arp, dhcp, udp
from ryu.lib import hub
import time
from collections import deque

MIN=12
factor=2
bloq_time=300
info=True

class flowMitigation(app_manager.RyuApp):
    
    OFP_VERSIONS=[ofproto_v1_3.OFP_VERSION]

    def __init__(self, *_args, **_kwargs):
        super(flowMitigation,self).__init__(*_args, **_kwargs)
        self.datapaths={}
        self.prev_stats={}
        hub.spawn(self.monitoreo)
        self.aut_ports=[1,2]
        self.historial={}

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        msg=ev.msg
        dp=msg.datapath
        ofp=dp.ofproto
        parser=dp.ofproto_parser
        
        
        self.datapaths[dp.id]=dp
        
        gototable1=parser.OFPInstructionGotoTable(1)
        match1=parser.OFPMatch()
        mod1=parser.OFPFlowMod(datapath=dp, table_id=0, priority=0, match=match1, instructions=[gototable1])
        dp.send_msg(mod1)
        
        port_request=parser.OFPPortDescStatsRequest(dp)
        dp.send_msg(port_request)
        
    @set_ev_cls(ofp_event.EventOFPPortDescStatsReply, MAIN_DISPATCHER)
    def switch_ports(self, ev):
        msg=ev.msg
        dp=msg.datapath
        ofp=dp.ofproto
        parser=dp.ofproto_parser 
        


        for port in msg.body:
            if port.port_no >= ofp.OFPP_MAX:
                continue
            match=parser.OFPMatch(in_port=port.port_no, eth_type=0x0806)

            gototable1=parser.OFPInstructionGotoTable(1)
            mod=parser.OFPFlowMod(datapath=dp, table_id=0, priority=150, match=match, instructions=[gototable1])
            dp.send_msg(mod)
            self.logger.info("Contador instalado en el puerto %s", port.port_no)
    

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def flow_stats(self, ev):
        msg=ev.msg
        dp=msg.datapath
        actual_time=time.time()
        dp_id=dp.id
        ofp=dp.ofproto
        parser=dp.ofproto_parser
        accumulated={}


        for stats in msg.body:
            if stats.priority != 150:
                continue

            port=stats.match['in_port']
            actual_pkt_count=stats.packet_count
            key=(dp_id, port)

            if key in self.prev_stats:
                before_time, before_pkt_count = self.prev_stats[key]
                dt=actual_time - before_time
                dpkts=actual_pkt_count - before_pkt_count
                rate=dpkts / dt
                

                if info==False: self.logger.debug("puerto: %s ---> %.2f ARP/s de tasa \n ", port, rate)
                else: self.logger.info("puerto: %s ---> %.2f ARP/s de tasa \n ", port, rate)


                if rate>10:
                    if port in self.aut_ports:
                        if info==False: self.logger.debug("Puerto %s, (autorizado), con %.2f ARP/s, no se bloquea", port, rate)
                        else: self.logger.info("Puerto %s, (autorizado), con %.2f ARP/s, no se bloquea", port, rate)

                    else:
                        self.logger.warning("El puerto %s, no autorizado esta mandando %.2f ARP/s, bloqueando por %s segundos", port, rate, bloq_time)
                        match=parser.OFPMatch(in_port=port)
                        inst=[parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, [])]
                        bloq=parser.OFPFlowMod(datapath=dp, table_id=0, priority=200, match=match, instructions=inst, hard_timeout=bloq_time)
                        dp.send_msg(bloq)
            self.prev_stats[key]=(actual_time, actual_pkt_count)
            if key not in self.historial:
                self.historial[key]=deque(maxlen=30)
            self.historial[key].append(actual_pkt_count)

            if len(self.historial[key])==30:
                accumulated_num=self.historial[key][-1]-self.historial[key][0]
                accumulated[port]=accumulated_num

            

        toEvaluate=[]
        for port, acc in accumulated.items():
            if port in self.aut_ports:
                if info==False: self.logger.debug("puerto %s, (autorizado), con %s arp acumulados, no se tiene en cuenta para la mediana", port, acc)
                else: self.logger.info("puerto %s, (autorizado), con %s arp acumulados, no se tiene en cuenta para la mediana", port, acc)

                continue
            toEvaluate.append(acc)
        if len(toEvaluate)<2:
            return
        toEvaluate.sort()
        median=toEvaluate[len(toEvaluate)//2] 
        if info==False: self.logger.debug("Acumulados: %s, median: %s",accumulated, median)
        else: self.logger.info("Acumulados: %s, median: %s",accumulated, median)

        for port, acc in accumulated.items():
            if port in self.aut_ports:
                if info==False: self.logger.debug("Puerto %s, (autorizado), con %s ARP acumulados, no se va a revisar para el arpspoofing", port, acc)
                else: self.logger.info("Puerto %s, (autorizado), con %s ARP acumulados, no se va a revisar para el arpspoofing", port, acc)

                continue
            if acc>=MIN and acc>factor*median:
                self.logger.warning("Puerto %s, con %s ARP acumulados, supera la mediana de %s ARP, se bloquea por %s segundos", port, acc, median, bloq_time)
                match=parser.OFPMatch(in_port=port)
                inst=[parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, [])]
                bloq=parser.OFPFlowMod(datapath=dp, table_id=0, priority=200, match=match, instructions=inst, hard_timeout=bloq_time)
                dp.send_msg(bloq)


    def monitoreo(self):
        while True:
            for dp in list(self.datapaths.values()):
                parser=dp.ofproto_parser
                stats_request=parser.OFPFlowStatsRequest(dp)
                dp.send_msg(stats_request)
            hub.sleep(1)
