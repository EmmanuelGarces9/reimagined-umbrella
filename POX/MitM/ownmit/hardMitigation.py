from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.util import dpidToStr
from pox.lib.addresses import EthAddr, IPAddr
from pox.lib.packet.ethernet import ethernet
from pox.lib.packet.arp import arp

mac_controlador = "00:00:00:10:00:00"
ip_controlador = "10.0.0.254"

log = core.getLogger()

class mitigacionARP(object):
    def __init__(self):
        self.tabla_verdad = {}  # IP -> MAC
        self.mac_a_puerto = {}  # MAC -> puerto
        self.pendientes = {}    # IP -> (MAC, Puerto)

        # Escuchamos cuando un switch se conecta y cuando llega un paquete
        core.openflow.addListeners(self)
        log.info("Controlador de Mitigacion ARP iniciado")

    def _handle_ConnectionUp(self, event):
        log.info("Switch %s conectado. Instalando regla para interceptar ARP...", dpidToStr(event.dpid))

        msg = of.ofp_flow_mod()
        # 0x0806 para arp
        msg.match.dl_type = 0x0806
        # Enviamos el paquete al controlador
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
            ip_destino = str(arp_packet.protodst)

            self.mac_a_puerto[mac_origen] = event.port

            # --- CASO A: La IP esta en proceso de verificación (pendientes) ---
            if ip_origen in self.pendientes:
                mac_pendiente, puerto_pendiente = self.pendientes[ip_origen]

                # la respuesta viene al controlador?
                if ip_destino == ip_controlador:
                    if mac_origen == mac_pendiente:
                        log.info("VERIFICACION EXITOSA, La IP %s es legitima (%s)", ip_origen, mac_origen)
                        self.tabla_verdad[ip_origen] = mac_origen
                        del self.pendientes[ip_origen]
                        self._enviar_paquete(event, mac_destino)
                    else:
                        log.warning("VERIFICACION FALLIDA, La IP %s fue reclamada por %s pero el real es %s", ip_origen, mac_pendiente, mac_origen)
                        self._bloquear_puerto(event.connection, puerto_pendiente)
                        del self.pendientes[ip_origen]
                    return
                
                # si no es para el controlador, entonces revisamos si es un reply (spoofing) o si es un request normal
                else:
                    if arp_packet.opcode == arp.REPLY:
                        log.warning("SPOOFING DETECTADO La IP %s intenta enganarr a %s sin responder a la verificacion.", ip_origen, ip_destino)
                        self._bloquear_puerto(event.connection, puerto_pendiente)
                        del self.pendientes[ip_origen]
                    else:
                        # Es un Request normal, lo dejamos pasar
                        self._enviar_paquete(event, mac_destino)
                    return

            # --- CASO B: La IP ya es conocida (Tabla de Verdad) ---
            elif ip_origen in self.tabla_verdad:
                mac_verdadera = self.tabla_verdad[ip_origen]
                
                if mac_verdadera != mac_origen:
                    log.warning("ATAQUE DETECTADO, La IP %s dice ser %s, pero la real es %s", ip_origen, mac_origen, mac_verdadera)
                    self._bloquear_puerto(event.connection, event.port)
                    # Curamos a la victima si el paquete iba dirigido a un host específico
                    if ip_destino != "0.0.0.0" and ip_destino != "255.255.255.255":
                        self._curar_victima(event.connection, ip_destino, ip_origen, mac_verdadera)
                    return
                else:
                    self._enviar_paquete(event, mac_destino)
                    return

            # --- CASO C: La IP es completamente nueva (Verificación Activa) ---
            else:
                self.pendientes[ip_origen] = (mac_origen, event.port)
                log.info("IP %s desconocida. Enviando verificacion ARP al puerto %s", ip_origen, event.port)

                # Realizamos la verificacion
                self._enviar_verificacion(event.connection, ip_origen, event.port, mac_origen)

                # Si es un REQUEST, lo dejamos pasar para no romper la red. Si es REPLY, lo retenemos.
                if arp_packet.opcode == arp.REQUEST:
                    self._enviar_paquete(event, mac_destino)
                else:
                    log.warning("IP %s desconocida y es REPLY. Reteniendo paquete para verificar...", ip_origen)
                return

        else:
            #si no es arp, conmuta normal 
            mac_origen = str(packet.src)
            self.mac_a_puerto[mac_origen] = event.port

            mac_destino = str(packet.dst)
            if mac_destino in self.mac_a_puerto:
                puerto = self.mac_a_puerto[mac_destino]
                msg = of.ofp_packet_out()
                msg.in_port = event.port
                msg.data = event.ofp.data
                msg.actions.append(of.ofp_action_output(port=puerto))
                event.connection.send(msg)
            else:
                msg = of.ofp_packet_out()
                msg.in_port = event.port
                msg.data = event.ofp.data
                msg.actions.append(of.ofp_action_output(port=of.OFPP_ALL))
                event.connection.send(msg)

    def _enviar_verificacion(self, connection, ip_a_verificar, puerto_salida, mac_sospechosa):
        eth = ethernet()
        eth.src = EthAddr(mac_controlador) 
        eth.dst = EthAddr("ff:ff:ff:ff:ff:ff")
        eth.type = ethernet.ARP_TYPE

        a = arp()
        a.opcode = arp.REQUEST
        a.hwsrc = EthAddr(mac_controlador)
        a.protosrc = IPAddr(ip_controlador) 
        a.hwdst = EthAddr("00:00:00:00:00:00")
        a.protodst = IPAddr(ip_a_verificar) 

        eth.payload = a

        msg = of.ofp_packet_out()
        msg.data = eth.pack()
        msg.actions.append(of.ofp_action_output(port=puerto_salida))
        connection.send(msg)

    def _enviar_paquete(self, event, mac_destino):
        msg = of.ofp_packet_out()
        msg.in_port = event.port
        msg.data = event.ofp.data

        if mac_destino == "ff:ff:ff:ff:ff:ff":
            msg.actions.append(of.ofp_action_output(port=of.OFPP_ALL))
            log.debug("Inundando ARP Request (Broadcast)")
        elif mac_destino in self.mac_a_puerto:
            puerto_salida = self.mac_a_puerto[mac_destino]
            msg.actions.append(of.ofp_action_output(port=puerto_salida))
            log.debug("Enviando ARP Reply directo al puerto %s", puerto_salida)
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

    def _curar_victima(self, connection, ip_victima, ip_real, mac_real):
        mac_victima = self.tabla_verdad.get(ip_victima)
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

        puerto_victima = self.mac_a_puerto.get(mac_victima)
        if puerto_victima:
            msg.actions.append(of.ofp_action_output(port=puerto_victima))
            connection.send(msg)
            log.info("Enviando paquete de curacion a IP %s (MAC: %s)", ip_victima, mac_victima)

def launch():
    core.registerNew(mitigacionARP)
