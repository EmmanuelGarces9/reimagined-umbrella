from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import CPULimitedHost
from mininet.link import TCLink
from mininet.util import irange,dumpNodeConnections
from mininet.log import setLogLevel
from mininet.cli import CLI
from mininet.node import OVSSwitch
from mininet.nodelib import LinuxBridge

class CustomTopo(Topo):
	def __init__(self,**opts):
		Topo.__init__(self, **opts)
		try:
            #Inserte su cรณdigo acรก
            #Recomendamos utilizar el método self.addSwitch('s%s'%i,cls=OVSSwitch,stp=1)
            #Los parámetros cls y stp hacen que en Mininet se utilicen switches que construyan un ST
			


		except Exception as e:
			return e

def runNet():
	topo=CustomTopo()
	return topo

if __name__ == '__main__':
	setLogLevel('info')
	runNet()
