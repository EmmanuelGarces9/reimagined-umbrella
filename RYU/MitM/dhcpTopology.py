from mininet.topo import Topo
from mininet.net import Mininet
from mininet.log import setLogLevel
from mininet.cli import CLI


class dhcpTopo(Topo):
    
    def build(self, hosts=3):
        
        s1=self.addSwitch('s1') 
        hostdhcp=self.addHost('dhcp', ip='10.0.0.254/24')
        self.addLink(hostdhcp, s1)
        for i in range (2, hosts+2):
            h=self.addHost('h%d' %i, ip=None)
            self.addLink(h,s1)

topos = {'dhcptopo' : dhcpTopo}

