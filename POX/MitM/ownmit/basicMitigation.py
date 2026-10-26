from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.util import dpidToStr
from pox.lib.addresses import EthAddr, IPAddr
from pox.lib.packet.ethernet import ethernet
from pox.lib.packet.arp import arp



log = core.getLogger()

class mitigacionARP(object):
    def __init__(self):
        self.tabla_verdad = {}  # IP -> MAC
        self.mac_a_puerto = {}  # MAC -> puerto


        # escuchamos cuando un switch se conecta y cuando llega un paquete
        core.openflow.addListeners(self)
        log.info("Controlador de Mitigacion ARP iniciado")

    def _handle_ConnectionUp(self, event):
        log.info("Switch %s conectado. Instalando regla para interceptar ARP...", dpidToStr(event.dpid))
        
        msg = of.ofp_flow_mod()
        # 0x0806 para arp
        msg.match.dl_type = 0x0806 
        #enviamos el paquete al controlador
        msg.actions.append(of.ofp_action_output(port=of.OFPP_CONTROLLER))
        msg.priority = 1000
        event.connection.send(msg)


    def _handle_PacketIn(self, event):
        packet = event.parsed

        if packet.find('arp'):
            arp_packet = packet.find('arp')
            mac_origen = str(packet.src)
            mac_destino = str(packet.dst) 
            ip_origen = str(arp_packet.protosrc)

            self.mac_a_puerto[mac_origen] = event.port

            # comprobacion de ataque o sano
            if ip_origen in self.tabla_verdad:
                mac_verdadera = self.tabla_verdad[ip_origen]

                if mac_verdadera != mac_origen:
                    log.warning("ATAQUE DETECTADO La IP %s dice ser la mac %s, pero la mac real es %s",
                                ip_origen, mac_origen, mac_verdadera)
                    self._bloquear_puerto(event.connection, event.port)
                    return
                else:
                    log.debug("arp sano de %s (%s)", ip_origen, mac_origen)
                    self._enviar_paquete(event, mac_destino)
            else:
                log.info("Aprendiendo nueva IP: %s = %s", ip_origen, mac_origen)
                self.tabla_verdad[ip_origen] = mac_origen
                self._enviar_paquete(event, mac_destino)


        else:
            # si no es ARP, conmuta normal
            mac_origen = str(packet.src)
            self.mac_a_puerto[mac_origen] = event.port
            
            mac_destino = str(packet.dst)
            if mac_destino in self.mac_a_puerto:
                # si conocemos el destino, lo enviamos directo
                puerto = self.mac_a_puerto[mac_destino]
                msg = of.ofp_packet_out()
                msg.in_port = event.port
                msg.data = event.ofp.data
                msg.actions.append(of.ofp_action_output(port=puerto))
                event.connection.send(msg)
            else:
                # si no lo conocemos, inundamos
                msg = of.ofp_packet_out()
                msg.in_port = event.port
                msg.data = event.ofp.data
                msg.actions.append(of.ofp_action_output(port=of.OFPP_ALL))
                event.connection.send(msg)



    def _enviar_paquete(self, event, mac_destino):
        msg = of.ofp_packet_out()
        msg.in_port = event.port
        msg.data = event.ofp.data

        # si es broadcast inundamos
        if mac_destino == "ff:ff:ff:ff:ff:ff":
            msg.actions.append(of.ofp_action_output(port=of.OFPP_ALL))
            log.debug("Inundando ARP Request (Broadcast)")

        # buscar el destino en la tabla
        elif mac_destino in self.mac_a_puerto:
            puerto_salida = self.mac_a_puerto[mac_destino]
            msg.actions.append(of.ofp_action_output(port=puerto_salida))
            log.debug("Enviando ARP Reply directo al puerto %s", puerto_salida)

        # si no conoce la mac inundamos
        else:
            msg.actions.append(of.ofp_action_output(port=of.OFPP_ALL))
            log.debug("MAC desconocida, inundando por seguridad")

        event.connection.send(msg)

    def _bloquear_puerto(self, connection, puerto_atacante):
        msg = of.ofp_flow_mod()
        msg.match.in_port = puerto_atacante
        msg.priority = 2000
        connection.send(msg)
        log.error("Puerto %s bloqueado por intento de ARP Spoofing.", puerto_atacante)

def launch():
    core.registerNew(mitigacionARP)

