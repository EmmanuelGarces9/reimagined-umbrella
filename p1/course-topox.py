from mininet.topo import Topo
from mininet.net import Mininet
from mininet.log import setLogLevel
from mininet.cli import CLI

class CustomTopo(Topo):

    def build(self, count = 1):

        s1 = self.addSwitch('s1')
        for i in range(1,count+1):
            h = self.addHost('h%d' %i)
            self.addLink(h,s1)


def startNet():
	net = Mininet(topo = CustomTopo(5))
	net.start()
	net.pingAll()
	net.stop()

if __name__ == '__main__':
   setLogLevel('info')
   startNet()
