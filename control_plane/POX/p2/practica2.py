#Parte de este código es tomada del curso de SDN realizado por el profesor
#Nick Feamster


from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.revent import *
from pox.lib.util import dpidToStr
from pox.lib.addresses import EthAddr
from collections import namedtuple
import os

#Adicione las clases y métodos que considere



log = core.getLogger()
policyFile = "%s/pox/pox/misc/firewall-policies.csv" % os.environ[ 'HOME' ]  

#Cree variables globales acá



class Firewall (EventMixin):

    def __init__ (self):
        self.listenTo(core.openflow)
        log.debug("Activando el firewall")

    def _handle_ConnectionUp (self, event):    
         #Adicione su código acá
        with open(policyFile, 'r') as infotop:
            for linea in infotop:
                if linea.startswith('id'):
                    continue
                datos = linea.strip().split(',')
                if len(datos)==3:
                     mac_1=datos[1].strip()
                     mac_2=datos[2].strip()
                     msg_ida = of.ofp_flow_mod()
                     msg_ida.priority = 100
                     msg_ida.match.dl_src = EthAddr(mac_1)
                     msg_ida.match.dl_dst = EthAddr(mac_2) 
                     event.connection.send(msg_ida)
                    

                     msg_vuelta = of.ofp_flow_mod()
                     msg_vuelta.priority = 100
                     msg_vuelta.match.dl_src = EthAddr(mac_2)
                     msg_vuelta.match.dl_dst = EthAddr(mac_1)
                     event.connection.send(msg_vuelta)


                     
                     log.debug("Creando regla: %s", datos[0])

        log.debug("Reglas instaladas en %s", dpidToStr(event.dpid))

def launch ():

    core.registerNew(Firewall)
