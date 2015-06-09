from mininet.net import Mininet
from mininet.topo import Topo
from mininet.cli import CLI
from mininet.node import *
from mininet.nodelib import LinuxBridge

import mininet

from optparse import OptionParser
import os, sys

ARBITER_IP="20.0.0.100"

# Connects all the host in the network to the root
# Namespace.  This enables the nodes to communicate with
# Arbiter, by using the 20.0.0.100 IP address.
def connect_hosts_to_root_ns(net):
	sw   = LinuxBridge('rtsw', dpid="001020203")
	root = Node('root', inNamespace=False)
	root0 = net.addLink(root, sw, arbiter_link=True)

	for host in net.hosts:
		ip = ""

		# Get the IP of the other interface
		try:
			ip = host.intfList()[0].ip
			ip = "20." + ".".join(ip.split(".")[1:])
		except Exception:
			print ("Failed to get the IP address of your interface."
				+ "  The offending host is: " + str(host))
			return False

		link = net.addLink(sw, host, arbiter_link=True)
		host.cmd('ifconfig ' + str(link.intf2) + ' ' + str(ip) + '/24')
		
	root.setIP(ARBITER_IP + "/32", intf=root0.intf1)
	root.cmd('route add -net 20.0.0.0/24 dev ' + str(root0.intf1));
	sw.start([])
	return True

class OneGbpsIntf(mininet.link.TCIntf):
	def __init__(self, *args, **kwargs):
		super(OneGbpsIntf, self).__init__(*args, **kwargs)
	
	def bwCmds(self, bw=None, **params):
		is_root = 'root' in self.name
		is_aux  = 'rtsw' in self.name
		is_sec  = 'eth1' in self.name

		if bw is None or is_root or is_aux or is_sec:
			return [], ' root '

		cmds   = [ '%s qdisc add dev %s root handle 5:0 htb default 1',
			  '%s class add dev %s parent 5:0 classid 5:1 htb ' +
			  'rate 1000Mbit burst 15k ceil 1250Mbit']
		parent = ' parent 5:1 '
		return cmds, parent

class FastpassLink(mininet.link.Link):
	def __init__( self, node1, node2, port1=None, port2=None,
			intfName1=None, intfName2=None,
			addr1=None, addr2=None, **params ):

		if not 'arbiter_link' in params:
			params = dict(bw=1000, max_queue_size=200)
		else:
			params = dict()

		super(FastpassLink, self).__init__(
				node1, node2, port1=port1, port2=port2,
				intfName1=intfName1, intfName2=intfName2,
				cls1=OneGbpsIntf,
				cls2=OneGbpsIntf,
				addr1=addr1, addr2=addr2,
				params1=params,
				params2=params )

def parse_options():
	parser = OptionParser()
	parser.add_option("-c", "--custom", dest="custom",
	    	help="The custom topology file.")
	parser.add_option("-t", "--topo", dest="topo", 
	    	help="Name of the topology in the topos dictionary")
	return parser.parse_args()

def module_name_from_file(filename):
	return os.path.splitext(filename)[0]

ENDC   = '\033[0m'
BOLD   = '\033[1m'
UNDERLINE = '\033[1m'
RED    = '\033[91m'
GREEN  = '\033[92m'
YELLOW = '\033[93m'
BLUE   = '\033[94m'

def cprint(color, text):
	print ("> " + color + text + ENDC)

if __name__ == '__main__':
	(options, args) = parse_options()
	cprint(RED, "Remember not to use eth1 for your interfaces!")

	cprint(BOLD, "----------------------------------------------------------------------")
	cprint(BOLD, "| For this part of the project, the bandwidth of the links in the    |")
	cprint(BOLD, "| fat-tree topology are limited to 1000Mbit.  Depending on the specs |")
	cprint(BOLD, "| of your machine, you might get slightly lower or higher bandwidth. |")
	cprint(BOLD, "----------------------------------------------------------------------")
	
	cprint(GREEN,"Importing the topology file.")
	topo = __import__(module_name_from_file(options.custom))
	if options.topo not in topo.topos:
		cprint(RED, "Unable to find a topology named: " + options.topo)
		sys.exit(0)

	cprint(GREEN,"Initiating Mininet.")
	imported_topo = topo.topos[options.topo]()
	net = Mininet(imported_topo, controller=RemoteController, 
		autoSetMacs = True, autoStaticArp = True, link=FastpassLink)

	cprint(GREEN, "Initiating the Arbiter network.")
	if (not connect_hosts_to_root_ns(net)):
		cprint(RED, "Failed to create the Arbiter network.")
		sys.exit()

	cprint (GREEN, "Hosts can access the Arbiter at: " + BOLD + YELLOW + str(ARBITER_IP))
	net.start()

	cprint (GREEN, "Initiating Mininet CLI.")
	CLI(net)

	net.stop()
