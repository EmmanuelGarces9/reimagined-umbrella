
from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.util import dpidToStr
from pox.lib.addresses import EthAddr, IPAddr
from pox.lib.packet.ethernet import ethernet
from pox.lib.packet.arp import arp
from pox.lib.packet.dhcp import dhcp
from pox.lib.packet.udp import udp

log = core.getLogger()

class mitigacionDhcp(object):
    def __init__(self):
        self.tabla_dhcp={}
        self.mac_puerto={}

        core.openflow.addListeners(self)
        log.info("Mitigacion iniciando")


    def _handle_ConnectionUp(self, event):
        log.info("Switch conectado, instalando reglas %s", dpidToStr(event.dpid))

        msg1=of.ofp_flow_mod()
        msg1.match.dl_type=0x0806 # tipo arp
        msg1.actions.append(of.ofp_action_output(port=of.OFPP_CONTROLLER))
        event.connection.send(msg1)

        msg2=of.ofp_flow_mod()
        msg2.match.dl_type=0x0800 # tipo ipv4
        msg2.match.nw_proto=17 # mensaje tipo udp
        msg2.match.tp_dst=68 # puerto de cliente dhcp
        msg2.actions.append(of.ofp_action_output(port=of.OFPP_CONTROLLER))
        event.connection.send(msg2)


    def _handle_PacketIn(self, event):
        packet = event.parsed

        arp_packet=packet.find('arp')
        ip_packet=packet.find('ipv4')

        # si el paquete es arp
        if arp_packet:
            self.comprobarArp(event)
            return

        # si el paquete es dhcp
        if ip_packet:
            udp_packet = ip_packet.find('udp')
            if udp_packet and udp_packet.dstport == 68:
                self.dhcpSnooping(event)
                return

        # conmutacion normal para el resto de paquetes
        mac_origen = str(packet.src)
        self.mac_puerto[mac_origen] = event.port
        mac_destino = str(packet.dst)

        # llamamos a la funcion enviar paquete
        self._enviar_paquete(event, mac_destino)


    def dhcpSnooping(self, event):
        dhcp_packet = event.parsed.find('dhcp')

        if not dhcp_packet:
            return

        # si no viene del puerto 1, es un dhcp falso
        if event.port != 1:
            log.warning("intento de dhcp falso en puerto %s", event.port)
            self._bloquear_puerto(event.connection, event.port)
            return

        # si es un ack, guardamos la verdad en la tabla
        if dhcp_packet.options.get(53) == b'\x05':
            mac_cliente = str(dhcp_packet.chaddr)
            ip_cliente = str(dhcp_packet.yiaddr)

            self.tabla_dhcp[ip_cliente] = mac_cliente
            log.info("dhcp snooping: ip %s asignada a mac %s", ip_cliente, mac_cliente)

        # reenviamos el paquete para que el cliente reciba su ip
        # como no conocemos al cliente aun, le pasamos la mac de broadcast para que inunde
        self._enviar_paquete(event, "ff:ff:ff:ff:ff:ff")


    def _bloquear_puerto(self, connection, puerto_atacante):
        msg = of.ofp_flow_mod()
        msg.match.in_port = puerto_atacante
        msg.priority = 2000
        connection.send(msg)
        log.error("puerto %s bloqueado por intento de ataque.", puerto_atacante)


    def comprobarArp(self, event):
        arp_packet = event.parsed.find('arp')
        mac_origen = str(event.parsed.src)
        mac_destino = str(event.parsed.dst)
        ip_origen = str(arp_packet.protosrc)
        ip_destino = str(arp_packet.protodst)

        # si la ip ya tiene un contrato dhcp
        if ip_origen in self.tabla_dhcp:
            mac_real = self.tabla_dhcp[ip_origen]

            if mac_real != mac_origen:
                # es un ataque
                log.warning("ataque arp detectado: la ip %s dice ser %s pero es %s", ip_origen, mac_origen, mac_real)
                self._bloquear_puerto(event.connection, event.port)
                # curamos a la victima (la ip destino)
                self._curar_victima(event.connection, ip_destino, ip_origen, mac_real)
                return

            log.debug("arp sano")
            self._enviar_paquete(event, mac_destino)

        # si la ip no esta en la tabla
        else:

            if event.port == 1:
                self._enviar_paquete(event, mac_destino)
                return

            if ip_origen not in ["0.0.0.0", "255.255.255.255"]:
                # es un atacante con ip estatica
                log.warning("ataque arp detectado: ip estatica no registrada %s", ip_origen)
                self._bloquear_puerto(event.connection, event.port)
                return
            else:
                # es un arp probe (host buscando ip)
                self._enviar_paquete(event, mac_destino)


    def _enviar_paquete(self, event, mac_destino):
        msg = of.ofp_packet_out()
        msg.in_port = event.port
        msg.data = event.ofp.data

        # si la mac destino es broadcast o no la conocemos, inundamos
        if mac_destino == "ff:ff:ff:ff:ff:ff" or mac_destino not in self.mac_puerto:
            msg.actions.append(of.ofp_action_output(port=of.OFPP_ALL))
        else:
            puerto = self.mac_puerto[mac_destino]
            msg.actions.append(of.ofp_action_output(port=puerto))

        event.connection.send(msg)


    def _curar_victima(self, connection, ip_victima, ip_real, mac_real):
        mac_victima = self.tabla_dhcp.get(ip_victima)
        if not mac_victima:
            return
        eth = ethernet()
        eth.src = EthAddr(mac_real)
        eth.dst = EthAddr(mac_victima)
        eth.type = ethernet.ARP_TYPE
        a = arp()
        a.opcode = arp.REPLY
        a.hwsrc = EthAddr(mac_real)
        a.protosrc = IPAddr(ip_real)
        a.hwdst = EthAddr(mac_victima)
        a.protodst = IPAddr(ip_victima)
        eth.payload = a
        msg = of.ofp_packet_out()
        msg.data = eth.pack()
        puerto_victima = self.mac_puerto.get(mac_victima)
        if puerto_victima:
            msg.actions.append(of.ofp_action_output(port=puerto_victima))
            connection.send(msg)


def launch():
    core.registerNew(mitigacionDhcp)










