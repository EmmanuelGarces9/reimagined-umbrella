
from mininet.topo import Topo
from mininet.net import Mininet
from mininet.log import setLogLevel
from mininet.cli import CLI
from mininet.node import CPULimitedHost, OVSSwitch
from mininet.link import TCLink
from mininet.util import dumpNodeConnections


class mytopo(Topo):
    
    def build(self, amount):
        
        switches=[]
        
        
        for i in range(0,amount):

            s=self.addSwitch('s%d' %i, cls=OVSSwitch, stp=True, failMode='standalone')
            h=self.addHost('h%d' %i)
            bw_in=int(input("Ancho de banda en Mbps:" ))
            delay_in=input("Retardo en ms: ")
            delay_in=delay_in + "ms"
            loss_in=float(input("Porcentaje de perdida: "))
            self.addLink(h,s,bw=bw_in, delay=delay_in, loss=loss_in, max_queue_size=1000, use_htb=True)
            switches.append(s)
        

        for i in range(len(switches)):

            for j in range(i+1, len(switches)):

                bw_in=int(input("Ancho de banda en Mbps:" ))
                delay_in=input("Retardo en ms: ")
                delay_in=delay_in + "ms"
                loss_in=float(input("Porcentaje de perdida: "))
                self.addLink(switches[i],switches[j], bw=bw_in, delay=delay_in, loss=loss_in, max_queue_size=1000, use_htb=True) 

                
topos = {'test' : mytopo}
