from mininet.net import Mininet
from mininet.cli import CLI

net = Mininet(controller=None)

# 1. Creamos los hosts
h1 = net.addHost('h1', ip='10.0.0.1/24', mac='00:00:00:00:00:01')
h2 = net.addHost('h2', ip='10.0.0.2/24', mac='00:00:00:00:00:02')
h3 = net.addHost('h3', ip='10.0.0.3/24', mac='00:00:00:00:00:03')
# 2. Creamos un switch "dummy" (solo para que Mininet cree los cables)
s1 = net.addSwitch('s1')

# 3. Conectamos los hosts
net.addLink(h1, s1)
net.addLink(h2, s1)
net.addLink(h3, s1)

# 4. Iniciamos la topología
net.start()

# 5. LA MAGIA: Movemos las interfaces del switch al espacio principal (PID 1)
# Esto saca los cables del control de Mininet y los deja libres para BMv2
s1.cmd('ip link set s1-eth1 netns 1')
s1.cmd('ip link set s1-eth2 netns 1')
s1.cmd('ip link set s1-eth3 netns 1')


print("=== Mininet listo ===")
print("Interfaces listas en el sistema: s1-eth1 (puerto 1) y s1-eth2 (puerto 2)")
print("AHORA VE A LA OTRA TERMINAL Y ARRANCA EL SWITCH P4.")
print("====================")

CLI(net)
