from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import CPULimitedHost
from mininet.link import TCLink
from mininet.util import irange,dumpNodeConnections
from mininet.log import setLogLevel
from mininet.cli import CLI

class CustomTopo(Topo):

    def __init__(self, linkopts1, count = 1, **opts):
        Topo.__init__(self, **opts)

        s1 = self.addSwitch('s1')
        for i in range(1,count+1):
            h = self.addHost('h%d' %i)
            self.addLink(h,s1,**linkopts1)

def perfTest():
	linkopts1 = {'bw':10, 'delay':'1ms', 'loss':0.1, 'max_queue_size':1000, 'use_htb':True}
	topo = CustomTopo(linkopts1,3)
	net = Mininet(topo=topo, host=CPULimitedHost, link=TCLink)
	net.start()
	net.pingAll()
	print ("perftest h1 - h2")
	h1, h2 = net.get('h1', 'h2')
	net.iperf((h1, h2))
	net.stop()

if __name__ == '__main__':
   setLogLevel('info')
   perfTest()
