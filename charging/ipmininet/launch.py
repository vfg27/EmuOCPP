import importlib
import re
import string
import time
from ipmininet.ipnet import IPNet
from mininet.term import makeTerm
from mininet.cli import CLI
from ipmininet.clean import cleanup, killprocs


import sys
import os

import yaml
sys.path.append('.')

import shutil
import secrets
from charging.db import add_user, remove_user

def generate_random_key(min_bytes=16, max_bytes=20):
    num_bytes = secrets.choice(range(min_bytes, max_bytes + 1))
    random_bytes = secrets.token_bytes(num_bytes)
    hex_string = random_bytes.hex()
    return hex_string

def generate_random_password(min_chars=16, max_chars=40):
    allowed_chars = string.ascii_letters + string.digits + "*-_=|@."
    password_length = secrets.choice(range(min_chars, max_chars + 1))
    random_password = ''.join(secrets.choice(allowed_chars) for _ in range(password_length))
    return random_password

def add_folders():
    os.mkdir('./serverConfigs')
    os.mkdir('./clientConfigs')

def remove_folders(clients):
    try:
        shutil.rmtree('./serverConfigs') 
    except Exception as e:
        pass
    try:
        shutil.rmtree('./clientConfigs')
    except Exception as e:
        pass
    try:
        for client in clients:
            try:
                shutil.rmtree(f'./charging/installedCertificates/{client.SN}')
            except:
                continue
    except Exception as e:
        pass

def set_IP(host:any , ips:list):
    for ip in ips:
        print(f'Ping {host.SN}  with {ip}...')
        ping_result = host.cmd(f'ping6 -c 5 {ip}')
        if re.search(r'(?:[2-9]|\d\d\d*) received', ping_result):
            print(f'{host.SN} connected with {ip}')
            with open(f'./clientConfigs/{host.SN}_config.yaml', 'r') as file:
                config = yaml.safe_load(file)
            if host.version == 'v1.6':
                config['ip'] = ip
            if 'profiles' in config and config['profiles'] != None:
                for profile in config['profiles']:
                    config['profiles'][profile]['ip']= ip
            with open(f'./clientConfigs/{host.SN}_config.yaml', 'w') as file:
                yaml.safe_dump(config, file, default_flow_style=False)
            break



def run_topology(topology_module_name):
    # Import the topology module from the topologies folder
    topo_module = importlib.import_module(f"topologies.{topology_module_name}")
    
    # Find the first class that is a subclass of IPTopo within the module
    topo_class = next(cls for name, cls in vars(topo_module).items() 
                      if isinstance(cls, type) and issubclass(cls, topo_module.IPTopo) and cls.__name__ != 'IPTopo')
    
    cleanup()
    
    # Instantiate the IP network with the imported topology
    net = IPNet(topo=topo_class(), allocate_IPs=True) # allocate_IPs= False if you want to specify the IPs

    
    # Start the network
    net.start()

    clients = []
    hosts = []

    for host in net.hosts:
        try:
            if host.type == 'client':
                clients.append(host)
        except:
            hosts.append(host)
            continue
  
    remove_folders(clients)

    add_folders()

    servFlag = False
    serverIPs = []

    servers = []
    dns = []

    for host in net.hosts:
        try:
            if host.type == 'client':
                print(f"Host {host.name} is a {host.type} with IPv6 {host.defaultIntf().ip6}")
                print(f" - Version: {host.version}, Profile: {host.profile}, SN: {host.SN} url: {host.url}")
                secProfiles = []
                os.popen(f'cp ./charging/client_config.yaml ./clientConfigs/{host.SN}_config.yaml')
                time.sleep(0.2)
                with open(f'./clientConfigs/{host.SN}_config.yaml', 'r') as file1, open(f'./charging/ipmininet/topologies/customTopo_config.yaml', 'r') as file2:
                    yaml1 = yaml.safe_load(file1)
                    yaml2 = yaml.safe_load(file2)
            
                for client in yaml2['clients']:
                    if yaml2['clients'][client]['name'] == host.name and yaml2['clients'][client]['version'] != 'v1.6':
                        yaml1['comm']['NetworkConfigurationPriority'] = yaml2['clients'][client]['priority']
                        yaml1['comm']['NetworkProfileConnectionAttempts'] = yaml2['clients'][client]['attempts']
                        yaml1['comm']['CertSigningWaitMinimum'] = yaml2['clients'][client]['wait']
                        yaml1['profiles'] = {}
                        yaml1['ip'] = None
                        if 'profiles' in yaml2['clients'][client]:
                            for profile in yaml2['clients'][client]['profiles']:
                                yaml1['profiles'][profile] = yaml2['clients'][client]['profiles'][profile]
                                secProfiles.append(yaml2['clients'][client]['profiles'][profile]['SP'])
                                yaml1['profiles'][profile]['message_timeout'] = 30
                    elif yaml2['clients'][client]['name'] == host.name and yaml2['clients'][client]['version'] == 'v1.6':
                        yaml1['HeartbeatInterval'] = 10
                        yaml1['comm'] = None
                        yaml1['profiles'] = None
                        yaml1['attempts'] = 2
                            
                # Save the modified yaml1 back to a file
                with open(f'./clientConfigs/{host.SN}_config.yaml', 'w') as file:
                    yaml.safe_dump(yaml1, file, default_flow_style=False)
                if secProfiles == []:
                    secProfiles.append(host.profile)
                if 3 in secProfiles:
                    os.mkdir(f'./charging/installedCertificates/{host.SN}')
                    os.mkdir(f'./charging/installedCertificates/{host.SN}/root')
                    os.popen(f'python3 ./charging/certificateCreation.py -id {host.SN} -type client')
                    os.popen(f'cp emuocpp_ttp_cert.pem ./charging/installedCertificates/{host.SN}/root')
                    time.sleep(1)
                    while True:
                        try:
                            with open(f'./clientConfigs/{host.SN}_config.yaml', 'r') as file:
                                config = yaml.safe_load(file)
                        except:
                            continue
                        break
                    
                    with open(f'./clientConfigs/{host.SN}_config.yaml', 'w') as file:
                        yaml.safe_dump(config, file, default_flow_style=False)
                if 1 in secProfiles or 2 in secProfiles:
                    if 2 in secProfiles and not 3 in secProfiles:
                        os.mkdir(f'./charging/installedCertificates/{host.SN}')
                        os.mkdir(f'./charging/installedCertificates/{host.SN}/root')
                        os.popen(f'cp emuocpp_ttp_cert.pem ./charging/installedCertificates/{host.SN}/root')
                    auth_key = generate_random_key() if host.version == 'v1.6' else generate_random_password()
                    add_user(user= host.SN, password=auth_key)
                    time.sleep(0.5)
                    while True:
                        try:
                            with open(f'./clientConfigs/{host.SN}_config.yaml', 'r') as file:
                                config = yaml.safe_load(file)
                        except:
                            continue
                        break
                    while True:
                        try:
                            config['security']['BasicAuthPassword'] = auth_key
                            print(f"AuthKey: {config['security']['BasicAuthPassword']}")
                        except Exception as e:
                            print(e)
                            time.sleep(2)
                            continue
                        break
                    with open(f'./clientConfigs/{host.SN}_config.yaml', 'w') as file:
                        yaml.safe_dump(config, file, default_flow_style=False)
                else:
                    add_user(user= host.SN, password=None)
                    time.sleep(0.5)
            elif host.type == 'server':
                print(f"Host {host.name} is a {host.type} with IPv6 {host.defaultIntf().ip6}")
                print(f" - Multiple: {host.multiple} URL: {host.url}, DNS: {host.dns}")
                servers.append(host)
                servFlag = True
                os.popen(f'cp ./charging/server_config.yaml ./serverConfigs/{host.name}_config.yaml')
                if host.url == None:
                    print(f'Adding host because url = {host.url}')
                    serverIPs.append(host.defaultIntf().ip6)
            elif host.type == 'dns':
                print(f"Host {host.name} is a DNS with IPv6 {host.defaultIntf().ip6}")
                dns.append(host)
        except AttributeError as e:
            print(f"Host {host.name} is a host with IPv6 {host.defaultIntf().ip6}")
    
    for client in clients:
        if client.url == None:
            print(f'Finding server for {client.SN}...')
            set_IP(host=client, ips=serverIPs)


    try:
        input("Press Enter to continue when you are OK with the configuration of the clients and the servers...")

        for dnsServer in dns:
            makeTerm(node= dnsServer, title=f'{dnsServer.name}', cmd=f"./venv/bin/python3 ./charging/dnsServer.py; exec bash")
        for server in servers:
            if server.url == None:
                makeTerm(node= server, title=f'{server.name}', cmd=f"./venv/bin/python3 ./charging/server.py -config_file ./serverConfigs/{server.name}_config.yaml -iface {server.name}-eth0 -ports 9000 9001 9002 9003 9004 9005 9006 9007 -multiple {server.multiple}; exec bash")
            else:
                makeTerm(node= server, title=f'{server.name}', cmd=f"echo 'Loading....'; sleep 25; ./venv/bin/python3 ./charging/server.py -config_file ./serverConfigs/{server.name}_config.yaml -iface {server.name}-eth0 -ports 9000 9001 9002 9003 9004 9005 9006 9007 -multiple {server.multiple} -dns {net.get(server.dns).defaultIntf().ip6} -url {server.url}; exec bash")
        
        hostT = True #Set to True if you want a terminal displayed for each host

        if hostT:
            print('Launching HOSTS terminals')
            for host in hosts:
                makeTerm(node= host, title=f'{host.name}', cmd=f"bash -i")


        clientT = False #Set to True if you want a terminal displayed for each client
        if not clientT:
            print('Loading...')
            time.sleep(35)
    
        for client in clients:
            time.sleep(1)
            if clientT:
                if client.url == None:
                    makeTerm(node= client, title=f'{client.name}', cmd=f"echo 'Loading....'; sleep 30; ./venv/bin/python3 ./charging/client.py -config_file ./clientConfigs/{client.SN}_config.yaml -ports 9000 9001 9002 9003 9004 9005 9006 9007 -version {client.version} -sec_profile {client.profile} -serial_number {client.SN}; exec bash")
                else:
                    makeTerm(node= client, title=f'{client.name}', cmd=f"echo nameserver {net.get(client.dns).defaultIntf().ip6} > /etc/resolv.conf; echo 'Loading....'; sleep 25; ./venv/bin/python3 ./charging/client.py -config_file ./clientConfigs/{client.SN}_config.yaml -version {client.version} -sec_profile {client.profile} -serial_number {client.SN} -url {client.url}; exec bash")
            else:
                if client.url == None:
                    client.cmd(f'{client.name}', cmd=f"./venv/bin/python3 ./charging/client.py -config_file ./clientConfigs/{client.SN}_config.yaml -ports 9000 9001 9002 9003 9004 9005 9006 9007 -version {client.version} -sec_profile {client.profile} -serial_number {client.SN} &")
                else:
                    client.cmd(f"echo nameserver {net.get(client.dns).defaultIntf().ip6} > /etc/resolv.conf; ./venv/bin/python3 ./charging/client.py -config_file ./clientConfigs/{client.SN}_config.yaml -version {client.version} -sec_profile {client.profile} -serial_number {client.SN} -url {client.url} &")
            
        # Keep the network running
        CLI(net)
    except:
        remove_folders(clients)
        try:
            for host in net.hosts:
                if host.type == 'client':
                    remove_user(user = host.SN)
        except Exception as e:
            pass
        
        print('Closing xterm terminals....')
        # Find PIDs of sudo bash processes
        pids = os.popen("ps -au | grep 'bash' | grep 'root' | awk '{print $2}'").read().strip().split()

        # Kill those processes
        for pid in pids:
            os.system(f'kill -9 {pid}')
        

    remove_folders(clients)
    try:
        for host in net.hosts:
            if host.type == 'client':
                remove_user(user = host.SN)
    except Exception as e:
        print(f"Error: {e}")

    cleanup()

    print('Closing xterm terminals....')
    # Find PIDs of sudo bash processes
    pids = os.popen("ps -au | grep 'bash' | grep 'root' | awk '{print $2}'").read().strip().split()

    # Kill those processes
    for pid in pids:
        os.system(f'kill -9 {pid}')

if __name__ == '__main__':
    
    # Specify the topology module name (without .py extension and inside topologies folder)
    topology_name = 'ConfigTopo'
    
    run_topology(topology_name)