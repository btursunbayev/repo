from fabrictestbed_extensions.fablib.attestable_switch import Attestable_Switch
from fabrictestbed_extensions.fablib.fablib import FablibManager as fablib_manager
from concurrent import futures
from IPython import get_ipython
from datetime import datetime
from time import sleep
from ipaddress import IPv6Address, IPv6Network
import os
import random
import tarfile
import enum
import shutil

class ConfigEnum(enum.IntEnum):
    SUBNET1 = 0
    SUBNET2 = enum.auto()
    H11IPV6 = enum.auto()
    H12IPV6 = enum.auto()
    H13IPV6 = enum.auto()
    H21IPV6 = enum.auto()
    H22IPV6 = enum.auto()
    S1MACS = enum.auto()
    S2MACS = enum.auto()
    H11MAC = enum.auto()
    H12MAC = enum.auto()
    H13MAC = enum.auto()
    H21MAC = enum.auto()
    H22MAC = enum.auto()
    H23MAC = enum.auto()
    S1IPV6 = enum.auto()
    S2IPV6 = enum.auto()
    TCPPORTS = enum.auto()
    UDPPORTS = enum.auto()

def setup(student_id, verbose=False, override=False, conf_ifaces=False):
    if student_id == "awolosewicz" and not override:
        raise Exception("Make sure to set student_id to your id (ex: awolosewicz)")
    config_name = student_id+"_p4_1.txt"
    try:
        config_file = open(config_name, 'r')
    except:
        raise Exception(f"Error: config file {config_name} not found. Make sure to upload it to the same directory as this notebook")
    configs = [line.rstrip('\n') for line in config_file]

    fablib = fablib_manager()
    slice_name = student_id+"_p4_1"
    build_slice = False
    try:
        vslice = fablib.get_slice(name=slice_name)
        print('Slice found - retrieving existing info\nIf slice setup did not previously complete, you must delete and rebuild it')
    except:
        vslice = fablib.new_slice(name=slice_name)
        build_slice = True
    host_cores = 2
    host_ram = 2
    host_disk = 10
    switch_cores = 2
    switch_ram = 2
    switch_disk = 10
    image = "default_ubuntu_20"
    site = "EDUKY"
    worker1 = "eduky-w16.fabric-testbed.net"
    worker2 = "eduky-w13.fabric-testbed.net"
    if build_slice:
        #Subnet 1
        h11 = vslice.add_node(name="h11", site=site, cores=host_cores, ram=host_ram, disk=host_disk, image=image, host=worker1)
        h11_iface = h11.add_component(model="NIC_Basic", name="h11p0").get_interfaces()[0]
        h11_iface.set_mode('manual')
        h12 = vslice.add_node(name="h12", site=site, cores=host_cores, ram=host_ram, disk=host_disk, image=image, host=worker1)
        h12_iface = h12.add_component(model="NIC_Basic", name="h12p0").get_interfaces()[0]
        h12_iface.set_mode('manual')
        h13 = vslice.add_node(name="h13", site=site, cores=host_cores, ram=host_ram, disk=host_disk, image=image, host=worker1)
        h13_iface = h13.add_component(model="NIC_Basic", name="h13p0").get_interfaces()[0]
        h13_iface.set_mode('manual')
        s1 = vslice.add_node(name="s1", site=site, cores=switch_cores, ram=switch_ram, disk=switch_disk, image=image, host=worker2)
        s1_iface0 = s1.add_component(model="NIC_Basic", name='s1p0').get_interfaces()[0]
        s1_iface1 = s1.add_component(model="NIC_Basic", name='s1p1').get_interfaces()[0]
        s1_iface2 = s1.add_component(model="NIC_Basic", name='s1p2').get_interfaces()[0]
        s1_iface3 = s1.add_component(model="NIC_Basic", name='s1p3').get_interfaces()[0]
        s1_iface0.set_mode('manual')
        s1_iface1.set_mode('manual')
        s1_iface2.set_mode('manual')
        s1_iface3.set_mode('manual')
        vslice.add_l2network(name='s1h11', interfaces=[s1_iface1, h11_iface])
        vslice.add_l2network(name='s1h12', interfaces=[s1_iface2, h12_iface])
        vslice.add_l2network(name='s1h13', interfaces=[s1_iface3, h13_iface])
        #Subnet 2
        h21 = vslice.add_node(name="h21", site=site, cores=host_cores, ram=host_ram, disk=host_disk, image=image, host=worker2)
        h21_iface = h21.add_component(model="NIC_Basic", name="h21p0").get_interfaces()[0]
        h21_iface.set_mode('manual')
        h22 = vslice.add_node(name="h22", site=site, cores=host_cores, ram=host_ram, disk=host_disk, image=image, host=worker2)
        h22_iface = h22.add_component(model="NIC_Basic", name="h22p0").get_interfaces()[0]
        h22_iface.set_mode('manual')
        h23 = vslice.add_node(name="h23", site=site, cores=host_cores, ram=host_ram, disk=host_disk, image=image, host=worker2)
        h23_iface = h23.add_component(model="NIC_Basic", name="h23p0").get_interfaces()[0]
        h23_iface.set_mode('manual')
        s2 = vslice.add_node(name="s2", site=site, cores=switch_cores, ram=switch_ram, disk=switch_disk, image=image, host=worker1)
        s2_iface0 = s2.add_component(model="NIC_Basic", name='s2p0').get_interfaces()[0]
        s2_iface1 = s2.add_component(model="NIC_Basic", name='s2p1').get_interfaces()[0]
        s2_iface2 = s2.add_component(model="NIC_Basic", name='s2p2').get_interfaces()[0]
        s2_iface3 = s2.add_component(model="NIC_Basic", name='s2p3').get_interfaces()[0]
        s2_iface0.set_mode('manual')
        s2_iface1.set_mode('manual')
        s2_iface2.set_mode('manual')
        s2_iface3.set_mode('manual')
        vslice.add_l2network(name='s2h21', interfaces=[s2_iface1, h21_iface])
        vslice.add_l2network(name='s2h22', interfaces=[s2_iface2, h22_iface])
        vslice.add_l2network(name='s2h23', interfaces=[s2_iface3, h23_iface])
        vslice.add_l2network(name='s1s2', interfaces=[s1_iface0, s2_iface0])
        vslice.submit()
    s1 = vslice.get_node(name='s1')
    h11 = vslice.get_node(name='h11')
    h12 = vslice.get_node(name='h12')
    h13 = vslice.get_node(name='h13')
    s2 = vslice.get_node(name='s2')
    h21 = vslice.get_node(name='h21')
    h22 = vslice.get_node(name='h22')
    h23 = vslice.get_node(name='h23')
    hosts = {
        'h11': h11,
        'h12': h12,
        'h13': h13,
        'h21': h21,
        'h22': h22,
        'h23': h23
    }
    switches = {
        's1': s1,
        's2': s2
    }
    if build_slice:
        print('Installing needed tools')
        install_switch = ('''sudo bash -c 'echo "2600:2701:5000:5001::c387:dfe2 download.opensuse.org" >> /etc/hosts'\n'''
                          'echo "deb [trusted=yes] http://download.opensuse.org/repositories/home:/p4lang/xUbuntu_20.04/ /" | sudo tee /etc/apt/sources.list.d/home:p4lang.list\n'
                          'curl -fsSL https://download.opensuse.org/repositories/home:p4lang/xUbuntu_20.04/Release.key | gpg --dearmor | sudo tee /etc/apt/trusted.gpg.d/home_p4lang.gpg > /dev/null\n'
                          'sudo apt-get update\n'
                          'sudo apt install -y p4lang-p4c net-tools python3-scapy\n'
                          'sudo sysctl net.ipv6.conf.all.forwarding=0\n')
        install_host = 'sudo apt-get update; sudo apt install -y net-tools python3-scapy'
        logging_command = """shopt -s histappend && echo -e 'HISTTIMEFORMAT="%T "\\nHISTFILESIZE=1000000\\nHISTSIZE=1000000\nPROMPT_COMMAND="history -a"' >> /home/ubuntu/.bashrc"""
        jobs = []
        jobs2 = []
        jobsu = []
        for switchname, switch in switches.items():
            jobs.append(switch.execute_thread(install_switch))
            jobs2.append(switch.execute_thread(logging_command))
            jobsu.append(switch.upload_directory_thread(f"nodes/{switchname}", "."))
            #if type(ip_address(switch.get_management_ip())) is IPv6Address:
            #    switch.execute("sudo sh -c 'echo nameserver 2a00:1098:2c::1 >> /etc/resolv.conf' && sudo sh -c 'echo nameserver 2a01:4f8:c2c:123f::1 >> /etc/resolv.conf' && sudo sh -c 'echo nameserver 2a00:1098:2b::1 >> /etc/resolv.conf'")
        for _, host in hosts.items():
            jobs.append(host.execute_thread(install_host))
            jobs2.append(host.execute_thread(logging_command))
            jobsu.append(host.upload_directory_thread(f"nodes/hosts", "."))
            #if type(ip_address(host.get_management_ip())) is IPv6Address:
            #    host.execute("sudo sh -c 'echo nameserver 2a00:1098:2c::1 >> /etc/resolv.conf' && sudo sh -c 'echo nameserver 2a01:4f8:c2c:123f::1 >> /etc/resolv.conf' && sudo sh -c 'echo nameserver 2a00:1098:2b::1 >> /etc/resolv.conf'")
        ctr = 0
        ctr_max = len(switches) + len(hosts)
        for _ in futures.as_completed(jobs):
            ctr += 1
            print(f'{ctr}/{ctr_max} installs finished')
        ctr = 0
        ctr_max = len(switches) + len(hosts)
        for _ in futures.as_completed(jobs2):
            ctr += 1
            print(f'{ctr}/{ctr_max} logging jobs finished')
        ctr = 0
        ctr_max = len(switches) + len(hosts)
        for _ in futures.as_completed(jobsu):
            ctr += 1
            print(f'{ctr}/{ctr_max} upload jobs finished')
        print('Finished installing needed tools')

    configs[ConfigEnum.S1MACS] = configs[ConfigEnum.S1MACS].split(',')
    configs[ConfigEnum.S2MACS] = configs[ConfigEnum.S2MACS].split(',')
    configs[ConfigEnum.TCPPORTS] = configs[ConfigEnum.TCPPORTS].split(',')
    configs[ConfigEnum.UDPPORTS] = configs[ConfigEnum.UDPPORTS].split(',')
    macs = {}
    macs['h11'] = [configs[ConfigEnum.H11MAC]]
    macs['h12'] = [configs[ConfigEnum.H12MAC]]
    macs['h13'] = [configs[ConfigEnum.H13MAC]]
    macs['h21'] = [configs[ConfigEnum.H21MAC]]
    macs['h22'] = [configs[ConfigEnum.H22MAC]]
    macs['h23'] = [configs[ConfigEnum.H23MAC]]
    macs['s1'] = configs[ConfigEnum.S1MACS]
    macs['s2'] = configs[ConfigEnum.S2MACS]
    ips = {}
    ips["h11"] = IPv6Address(configs[ConfigEnum.H11IPV6])
    ips["h12"] = IPv6Address(configs[ConfigEnum.H12IPV6])
    ips["h13"] = IPv6Address(configs[ConfigEnum.H13IPV6])
    ips["h21"] = IPv6Address(configs[ConfigEnum.H21IPV6])
    ips["h22"] = IPv6Address(configs[ConfigEnum.H22IPV6])
    ips['s1'] = IPv6Address(configs[ConfigEnum.S1IPV6])
    ips['s2'] = IPv6Address(configs[ConfigEnum.S2IPV6])
    ifaces = {}
    ifaces["h11"] = h11.get_interface(network_name='s1h11')
    ifaces["h12"] = h12.get_interface(network_name='s1h12')
    ifaces["h13"] = h13.get_interface(network_name='s1h13')
    ifaces["h21"] = h21.get_interface(network_name='s2h21')
    ifaces["h22"] = h22.get_interface(network_name='s2h22')
    ifaces["h23"] = h23.get_interface(network_name='s2h23')
    ifaces['s1'] = [s1.get_interface(network_name='s1s2'),
                    s1.get_interface(network_name='s1h11'),
                    s1.get_interface(network_name='s1h12'),
                    s1.get_interface(network_name='s1h13')]
    ifaces['s2'] = [s2.get_interface(network_name='s1s2'),
                    s2.get_interface(network_name='s2h21'),
                    s2.get_interface(network_name='s2h22'),
                    s2.get_interface(network_name='s2h23')]
    nhop_macs = {}
    nhop_macs["h11"] = macs['s1'][1]
    nhop_macs["h12"] = macs['s1'][2]
    nhop_macs["h13"] = macs['s1'][3]
    nhop_macs["h21"] = macs['s2'][1]
    nhop_macs["h22"] = macs['s2'][2]
    nhop_macs["h23"] = macs['s2'][3]
    subnets = {
        'h11': IPv6Network(configs[ConfigEnum.SUBNET1]),
        'h12': IPv6Network(configs[ConfigEnum.SUBNET1]),
        'h13': IPv6Network(configs[ConfigEnum.SUBNET1]),
        'h21': IPv6Network(configs[ConfigEnum.SUBNET2]),
        'h22': IPv6Network(configs[ConfigEnum.SUBNET2]),
        'h23': IPv6Network(configs[ConfigEnum.SUBNET2]),
        's1': IPv6Network(configs[ConfigEnum.SUBNET1]),
        's2': IPv6Network(configs[ConfigEnum.SUBNET2])
    }
    gateways = {
        'h11': [ips['s1'], 's1', 's1p1'],
        'h12': [ips['s1'], 's1', 's1p2'],
        'h13': [ips['s1'], 's1', 's1p3'],
        'h21': [ips['s2'], 's2', 's2p1'],
        'h22': [ips['s2'], 's2', 's2p2'],
        'h23': [ips['s2'], 's2', 's2p3']
    }
    
    jobs = []
    host_subnets = [configs[ConfigEnum.SUBNET1], configs[ConfigEnum.SUBNET2]]
    if build_slice or conf_ifaces:
        print("Configuring node interfaces")
        for switchname, switch in switches.items():
            print(f"Configuring {switchname}...", end="")
            for i, iface in enumerate(ifaces[switchname]):
                iface.ip_addr_add(ips[switchname], subnets[switchname])
                iface_dev = iface.get_device_name()
                commands = ""
            
                command = f'sudo ip link set dev {iface_dev} down; '
                if verbose: print(command)
                commands += command
                
                command = f'sudo ip link set dev {iface_dev} address {macs[switchname][i]}; '
                if verbose: print(command)
                commands += command
            
                command = f'sudo ip link set dev {iface_dev} up;'
                if verbose: print(command)
                commands += command
            
                command = f'sudo ip -6 addr add {ips[switchname]} dev {iface_dev}; '
                if verbose: print(command)
                commands += command
            
                jobs.append(switch.execute_thread(commands))
            print("Done")
                
        for hostname, host in hosts.items():
            print(f"Configuring {hostname}...", end="")
            iface = ifaces[hostname]
            iface_dev = iface.get_device_name()
            commands = ""
            
            command = f'sudo ip link set dev {iface_dev} down; '
            if verbose: print(command)
            commands += command
            
            command = f'sudo ip link set dev {iface_dev} address {macs[hostname][0]}; '
            if verbose: print(command)
            commands += command
            
            command = f'sudo ip link set dev {iface_dev} up; '
            if verbose: print(command)
            commands += command

            if hostname != "h23":
                command = f'sudo ip -6 addr add {ips[hostname]} dev {iface_dev}; '
                if verbose: print(command)
                commands += command
            
            command = f'sudo ip -6 neigh replace {gateways[hostname][0]} lladdr {nhop_macs[hostname]} dev {iface_dev}; '
            if verbose: print(command)
            commands += command
            
            command = f'sudo ip -6 route replace {gateways[hostname][0]} dev {iface_dev}; '
            if verbose: print(command)
            commands += command
            
            for destname, dest in hosts.items():
                if destname == hostname or destname == "h23":
                    continue
                command = f'sudo ip -6 route replace {ips[destname]} via {gateways[hostname][0]}; '
                if verbose: print(command)
                commands += command
            
            command = f'sudo ip -6 route replace {subnets[hostname][0]} dev {iface_dev}; '
            if verbose: print(command)
            commands += command
            
            jobs.append(host.execute_thread(commands))
            print("Done")
        print("\n")
        ctr = 0
        ctr_max = len(switches)*4 + len(hosts)
        for _ in futures.as_completed(jobs):
            ctr += 1
            print(f'{ctr}/{ctr_max} address configuration jobs finished')
        print('Finished configuring addresses')
        
        
    slice_values = {}
    slice_values['configs'] = configs
    slice_values['ips'] = ips
    slice_values['macs'] = macs
    slice_values['ifaces'] = ifaces
    slice_values['subnets'] = subnets
    slice_values['hosts'] = hosts
    slice_values['switches'] = switches
    slice_values['slice'] = vslice
    slice_values['gateways'] = gateways
    initialize_logging()
    return slice_values

def reconfigure(student_id, vslice, hosts, switches, verbose=False):
    config_name = student_id+"_p4_1.txt"
    try:
        config_file = open(f'submissions/{student_id}/{config_name}', 'r')
    except:
        raise Exception(f"Error: config file {config_name} not found. Make sure to upload it to the same directory as this notebook")
    configs = [line.rstrip('\n') for line in config_file]
    configs[ConfigEnum.S1MACS] = configs[ConfigEnum.S1MACS].split(',')
    configs[ConfigEnum.S2MACS] = configs[ConfigEnum.S2MACS].split(',')
    configs[ConfigEnum.TCPPORTS] = configs[ConfigEnum.TCPPORTS].split(',')
    configs[ConfigEnum.UDPPORTS] = configs[ConfigEnum.UDPPORTS].split(',')
    macs = {}
    macs['h11'] = [configs[ConfigEnum.H11MAC]]
    macs['h12'] = [configs[ConfigEnum.H12MAC]]
    macs['h13'] = [configs[ConfigEnum.H13MAC]]
    macs['h21'] = [configs[ConfigEnum.H21MAC]]
    macs['h22'] = [configs[ConfigEnum.H22MAC]]
    macs['h23'] = [configs[ConfigEnum.H23MAC]]
    macs['s1'] = configs[ConfigEnum.S1MACS]
    macs['s2'] = configs[ConfigEnum.S2MACS]
    ips = {}
    ips["h11"] = IPv6Address(configs[ConfigEnum.H11IPV6])
    ips["h12"] = IPv6Address(configs[ConfigEnum.H12IPV6])
    ips["h13"] = IPv6Address(configs[ConfigEnum.H13IPV6])
    ips["h21"] = IPv6Address(configs[ConfigEnum.H21IPV6])
    ips["h22"] = IPv6Address(configs[ConfigEnum.H22IPV6])
    ips['s1'] = IPv6Address(configs[ConfigEnum.S1IPV6])
    ips['s2'] = IPv6Address(configs[ConfigEnum.S2IPV6])
    ifaces = {}
    ifaces["h11"] = hosts['h11'].get_interface(network_name='s1h11')
    ifaces["h12"] = hosts['h12'].get_interface(network_name='s1h12')
    ifaces["h13"] = hosts['h13'].get_interface(network_name='s1h13')
    ifaces["h21"] = hosts['h21'].get_interface(network_name='s2h21')
    ifaces["h22"] = hosts['h22'].get_interface(network_name='s2h22')
    ifaces["h23"] = hosts['h23'].get_interface(network_name='s2h23')
    ifaces['s1'] = [switches['s1'].get_interface(network_name='s1s2'),
                    switches['s1'].get_interface(network_name='s1h11'),
                    switches['s1'].get_interface(network_name='s1h12'),
                    switches['s1'].get_interface(network_name='s1h13')]
    ifaces['s2'] = [switches['s2'].get_interface(network_name='s1s2'),
                    switches['s2'].get_interface(network_name='s2h21'),
                    switches['s2'].get_interface(network_name='s2h22'),
                    switches['s2'].get_interface(network_name='s2h23')]
    nhop_macs = {}
    nhop_macs["h11"] = macs['s1'][1]
    nhop_macs["h12"] = macs['s1'][2]
    nhop_macs["h13"] = macs['s1'][3]
    nhop_macs["h21"] = macs['s2'][1]
    nhop_macs["h22"] = macs['s2'][2]
    nhop_macs["h23"] = macs['s2'][3]
    subnets = {
        'h11': IPv6Network(configs[ConfigEnum.SUBNET1]),
        'h12': IPv6Network(configs[ConfigEnum.SUBNET1]),
        'h13': IPv6Network(configs[ConfigEnum.SUBNET1]),
        'h21': IPv6Network(configs[ConfigEnum.SUBNET2]),
        'h22': IPv6Network(configs[ConfigEnum.SUBNET2]),
        'h23': IPv6Network(configs[ConfigEnum.SUBNET2]),
        's1': IPv6Network(configs[ConfigEnum.SUBNET1]),
        's2': IPv6Network(configs[ConfigEnum.SUBNET2])
    }
    gateways = {
        'h11': [ips['s1'], 's1', 's1p1'],
        'h12': [ips['s1'], 's1', 's1p2'],
        'h13': [ips['s1'], 's1', 's1p3'],
        'h21': [ips['s2'], 's2', 's2p1'],
        'h22': [ips['s2'], 's2', 's2p2'],
        'h23': [ips['s2'], 's2', 's2p3']
    }
    
    jobs = []
    host_subnets = [configs[ConfigEnum.SUBNET1], configs[ConfigEnum.SUBNET2]]
    if verbose: print("Configuring node interfaces")
    for switchname, switch in switches.items():
        if verbose: print(f"Configuring {switchname}...", end="")
        for i, iface in enumerate(ifaces[switchname]):
            iface_dev = iface.get_device_name()
            commands = ""
            
            command = f'sudo ip link set dev {iface_dev} down; '
            if verbose: print(command)
            commands += command
        
            command = f'sudo ip link set dev {iface_dev} down; '
            if verbose: print(command)
            commands += command
            
            command = f'sudo ip link set dev {iface_dev} address {macs[switchname][i]}; '
            if verbose: print(command)
            commands += command
        
            command = f'sudo ip link set dev {iface_dev} up;'
            if verbose: print(command)
            commands += command
        
            command = f'sudo ip -6 addr replace {ips[switchname]} dev {iface_dev}; '
            if verbose: print(command)
            commands += command
        
            jobs.append(switch.execute_thread(commands))
        if verbose: print("Done")
            
    for hostname, host in hosts.items():
        if verbose: print(f"Configuring {hostname}...", end="")
        iface = ifaces[hostname]
        iface_dev = iface.get_device_name()
        commands = ""
        
        command = f'sudo ip link set dev {iface_dev} down; '
        if verbose: print(command)
        commands += command
        
        command = f'sudo ip link set dev {iface_dev} address {macs[hostname][0]}; '
        if verbose: print(command)
        commands += command
        
        command = f'sudo ip link set dev {iface_dev} up; '
        if verbose: print(command)
        commands += command

        if hostname != "h23":
            command = f'sudo ip -6 addr replace {ips[hostname]} dev {iface_dev}; '
            if verbose: print(command)
            commands += command
        
        command = f'sudo ip -6 neigh replace {gateways[hostname][0]} lladdr {nhop_macs[hostname]} dev {iface_dev}; '
        if verbose: print(command)
        commands += command
        
        command = f'sudo ip -6 route replace {gateways[hostname][0]} dev {iface_dev}; '
        if verbose: print(command)
        commands += command
        
        for destname, dest in hosts.items():
            if destname == hostname or destname == "h23":
                continue
            command = f'sudo ip -6 route replace {ips[destname]} via {gateways[hostname][0]}; '
            if verbose: print(command)
            commands += command
        
        command = f'sudo ip -6 route replace {subnets[hostname][0]} dev {iface_dev}; '
        if verbose: print(command)
        commands += command
        
        jobs.append(host.execute_thread(commands))
        if (verbose): print("Done")
    if (verbose): print("\n")
    ctr = 0
    ctr_max = len(switches)*4 + len(hosts)
    for _ in futures.as_completed(jobs):
        ctr += 1
        if (verbose): print(f'{ctr}/{ctr_max} address configuration jobs finished')
    if (verbose): print('Finished configuring addresses')
    shutil.copyfile(f'submissions/{student_id}/add_rules_s1.sh', 'add_rules_s1.sh')
    shutil.copyfile(f'submissions/{student_id}/add_rules_s2.sh', 'add_rules_s2.sh')
    shutil.copyfile(f'submissions/{student_id}/assignment.p4', 'assignment.p4')
        
    slice_values = {}
    slice_values['configs'] = configs
    slice_values['ips'] = ips
    slice_values['macs'] = macs
    slice_values['ifaces'] = ifaces
    slice_values['subnets'] = subnets
    slice_values['hosts'] = hosts
    slice_values['switches'] = switches
    slice_values['slice'] = vslice
    slice_values['gateways'] = gateways
    return slice_values

def start_switches(switches, verbose):
    print('Starting switches')
    jobs = []
    for switchname, switch in switches.items():
        port_sequence = ""
        p0 = switch.get_component(name=switchname+"p0").get_interfaces()[0]
        p1 = switch.get_component(name=switchname+"p1").get_interfaces()[0]
        p2 = switch.get_component(name=switchname+"p2").get_interfaces()[0]
        p3 = switch.get_component(name=switchname+"p3").get_interfaces()[0]
        port_sequence = f'-i 0@{p0.get_device_name()} -i 1@{p1.get_device_name()} -i 2@{p2.get_device_name()} -i 3@{p3.get_device_name()}'
        switch.upload_file("assignment.p4", "assignment.p4")
        stdout, stderr = switch.execute("p4c --target bmv2 --arch v1model assignment.p4")
        print(f"Compiling P4...\n{stdout}\n{stderr}")
        jobs.append(switch.execute_thread(f'sudo simple_switch {port_sequence} assignment.json --log-file ~/switch.log --log-flush -- --enable-swap &'))
    sleep(5)
    for switchname, switch in switches.items():
        switch.upload_file(f"add_rules_{switchname}.sh", f"add_rules_{switchname}.sh")
        switch.execute(f'chmod u+x add_rules_{switchname}.sh; ./add_rules_{switchname}.sh', quiet=(not verbose))
    print('Switches started')

def stop_switches(switches, verbose):
    for _, switch in switches.items():
        switch.execute('sudo killall simple_switch', quiet=(not verbose))

# Define a callback function to log executed code
def log_code_execution(result):
    log_file = "jupyter_code_log.txt"
    with open(log_file, "a") as f:
        f.write("#" * 80 + "\n")
        f.write(f"## Executed at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"## Cell: {result.info.cell_id}\n\n")
        f.write(result.info.raw_cell + "\n\n")
            
def initialize_logging():
    # Define the log file name
    log_file = "jupyter_code_log.txt"
    
    # Initialize the log file with a header
    if not os.path.exists(log_file):
        with open(log_file, "a") as f:
            f.write(f"### Code Execution Log - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} ###\n\n")
    
    # Register the callback function
    ip = get_ipython()
    if ip is not None:
        ip.events.register("post_run_cell", log_code_execution)
        print(f"Code execution will be logged to '{log_file}'.")
    else:
        print("This script must be run in a Jupyter Notebook.")

def create_tar(student_id, hosts, switches, override=False):
    if (student_id is None or student_id == "awolosewicz") and not override:
        raise Exception("Please make sure you set your student ID!")
    jobs = []
    for nodename, node in hosts.items():
        jobs.append(node.download_file_thread(f"nodes/{nodename}_bash_history", "/home/ubuntu/.bash_history"))
    for nodename, node in switches.items():
        jobs.append(node.download_file_thread(f"nodes/{nodename}_bash_history", "/home/ubuntu/.bash_history"))
    futures.wait(jobs)
    with tarfile.open(f"{student_id}.tar.gz", "w:gz") as tar:
        tar.add(".", arcname=os.path.basename("."))
    print(f"Done! Please submit {student_id}.tar.gz on Canvas!")

def print_values(configs, macs, ips):
    print(f"s1's MAC addresses are (in order from port 0 to port 3):\n{macs['s1'][0]}\n{macs['s1'][1]}\n{macs['s1'][2]}\n{macs['s1'][3]}")
    print(f"s2's MAC addresses are (in order from port 0 to port 3):\n{macs['s2'][0]}\n{macs['s2'][1]}\n{macs['s2'][2]}\n{macs['s2'][3]}")
    print("For the above, s1 and s2 are connected to each other on their port 0. Port 1 connects to h11 or h21, port 2 to h12 or h22, and port 3 to h13 or h23.")
    print(f"h11's MAC address is {macs['h11'][0]} and its IPv6 address is {ips['h11']}")
    print(f"h12's MAC address is {macs['h12'][0]} and its IPv6 address is {ips['h12']}")
    print(f"h13's MAC address is {macs['h13'][0]} and its IPv6 address is {ips['h13']}")
    print(f"h21's MAC address is {macs['h21'][0]} and its IPv6 address is {ips['h21']}")
    print(f"h22's MAC address is {macs['h22'][0]} and its IPv6 address is {ips['h22']}")
    print(f"The allowed TCP ports are:", end="")
    for port in configs[ConfigEnum.TCPPORTS]:
        print(f' {port}', end="")
    print(f"\nThe allowed UDP ports are:", end="")
    for port in configs[ConfigEnum.UDPPORTS]:
        print(f' {port}', end="")
    print("\nA reminder that in the topology, h23 is ignored and autoconfigured later.")

def ping_test(hosts, ips):
    pingscore = 0
    for hostname, host in hosts.items():
        counter = 0
        if hostname == "h23": continue
        for destname, dest in hosts.items():
            if destname == hostname or destname == "h23": continue
            if host.ping_test(ips[destname]):
                counter += 1
            else:
                print(f"{hostname} failed to ping {destname}")
        if counter == 4:
            print(f"{hostname} 4/4 pings successful, +0.5pts")
            pingscore += 0.5
        else:
            print(f"{hostname} {counter}/4 pings successful, 0pts")
    print(f"Total ping score: {pingscore}/2.5pts")
    return pingscore

def port_test(hosts, ips, configs, ifaces, student_id, verbose=False):
    portscore = 0
    random.seed(a=student_id)
    tcp_ports = configs[ConfigEnum.TCPPORTS]
    udp_ports = configs[ConfigEnum.UDPPORTS]
    tcp_good = random.choice(tcp_ports)
    tcp_bad = random.randint(1, 65535)
    udp_good = random.choice(udp_ports)
    udp_bad = random.randint(1, 65535)
    while tcp_bad in tcp_ports:
        tcp_bad = random.randint(1, 65535)
    while udp_bad in udp_ports:
        udp_bad = random.randint(1, 65535)
    sender = random.choice([hosts['h11'], hosts['h12'], hosts['h13']])
    sender_name = sender.get_name()
    receiver = random.choice([hosts['h21'], hosts['h22']])
    receiver_name = receiver.get_name()
    sender.execute("chmod u+x hosts/send.py", quiet=(not verbose))
    sender.execute("chmod u+x hosts/receive.py", quiet=(not verbose))
    receiver.execute("chmod u+x hosts/send.py", quiet=(not verbose))
    receiver.execute("chmod u+x hosts/receive.py", quiet=(not verbose))
    print(f"{receiver_name}: Starting receiver")
    rx_thread = receiver.execute_thread(f"sudo ./hosts/receive.py --host_iface {ifaces[receiver_name].get_device_name()}")
    sleep(5)
    iface_dev = ifaces[sender_name].get_device_name()
    if verbose: print(f"TCP good: {tcp_good}, TCP bad: {tcp_bad}, UDP good: {udp_good}, UDP bad: {udp_bad}")
        
    print(f"{sender_name}: Send allowed TCP packets")
    command = f"sudo ./hosts/send.py {ips[receiver_name]} tcp {tcp_good} {tcp_bad} --host_iface {iface_dev}"
    if verbose: print(command)
    sender.execute(command, quiet=(not verbose))
    sleep(0.1)
    
    command = f"sudo ./hosts/send.py {ips[receiver_name]} tcp {tcp_bad} {tcp_good} --host_iface {iface_dev}"
    if verbose: print(command)
    sender.execute(command, quiet=(not verbose))
    sleep(0.1)
    
    print(f"{sender_name}: Send non-allowed TCP packet")
    command = f"sudo ./hosts/send.py {ips[receiver_name]} tcp {tcp_bad} {tcp_bad} --host_iface {iface_dev}"
    if verbose: print(command)
    sender.execute(command, quiet=(not verbose))
    sleep(0.1)
    
    print(f"{sender_name}: Send allowed UDP packets")
    command = f"sudo ./hosts/send.py {ips[receiver_name]} udp {udp_good} {udp_bad} --host_iface {iface_dev}"
    if verbose: print(command)
    sender.execute(command, quiet=(not verbose))
    sleep(0.1)

    command = f"sudo ./hosts/send.py {ips[receiver_name]} udp {udp_bad} {udp_good} --host_iface {iface_dev}"
    if verbose: print(command)
    sender.execute(command, quiet=(not verbose))
    sleep(0.1)
    
    print(f"{sender_name}: Send non-allowed UDP packet")
    command = f"sudo ./hosts/send.py {ips[receiver_name]} udp {udp_bad} {udp_bad} --host_iface {iface_dev}"
    if verbose: print(command)
    sender.execute(command, quiet=(not verbose))
    sleep(0.1)
    
    receiver.execute("sudo killall python3", quiet=(not verbose))
    rx_results = rx_thread.result()[0].split('\n')
    if verbose: print(rx_results)
    count_tcp = 0
    count_udp = 0
    for result in rx_results[1:]:
        if result == "Received TCP":
            count_tcp += 1
        elif result == "Received UDP":
            count_udp += 1
    if count_tcp == 1:
        print("Received 1 TCP packet, should be 2. +0pts")
    elif count_tcp == 2:
        portscore += 2.5
        print("Received 2 TCP packets. 2.5pts")
    elif count_tcp == 3:
        print("Received 3 TCP packets, should be 2. +0pts")
    if count_udp == 1:
        print("Received 1 UDP packet, should be 2. +0pts")
    elif count_udp == 2:
        portscore += 2.5
        print("Received 2 UDP packets. 2.5pts")
    elif count_udp == 3:
        print("Received 3 UDP packets, should be 2. +0pts")
    print(f"Total port score: {portscore}/5.0pts")
    return portscore

def h23_test(hosts, ips, switches, ifaces, configs, macs, gateways, verbose):
    s2 = switches['s2']
    h23 = hosts['h23']
    s2.execute("sudo killall simple_switch", quiet=(not verbose))
    s2_iface0_name = ifaces['s2'][0].get_device_name()
    s2_iface1_name = ifaces['s2'][1].get_device_name()
    s2_iface2_name = ifaces['s2'][2].get_device_name()
    s2_iface3_name = ifaces['s2'][3].get_device_name()
    s2.execute_thread(f"sudo simple_switch -i 0@{s2_iface0_name} -i 1@{s2_iface1_name} -i 2@{s2_iface2_name} -i 3@{s2_iface3_name} ~/s2/tester.json --log-file ~/switch.log --log-flush -- --enable-swap &")
    sleep(5)
    hexchars = ['1', '2', '3', '4', '5', '6', '7', '8', '9', '0', 'a', 'b', 'c', 'd', 'e', 'f']
    subnet1 = configs[ConfigEnum.SUBNET1]
    subnet2 = configs[ConfigEnum.SUBNET2]
    h23_ipv6 = None
    try:
        h23_ipv6_old = ips['h23']
        h23_ipv6 = str(subnet2).split('/')[0]+random.choice(hexchars)+random.choice(hexchars)+random.choice(hexchars)+random.choice(hexchars)
    except:
        h23_ipv6 = str(subnet2).split('/')[0]+random.choice(hexchars)+random.choice(hexchars)+random.choice(hexchars)+random.choice(hexchars)
        h23_ipv6_old = h23_ipv6
    command = f"chmod u+x s2/tester_rules_s2.sh && ./s2/tester_rules_s2.sh {macs['s2'][0]} {macs['s2'][1]} {macs['s2'][2]} {macs['s2'][3]} {macs['h21'][0]} {macs['h22'][0]} {macs['h23'][0]} {ips['h21']} {ips['h22']} {h23_ipv6} {ips['s1']} {macs['s1'][0]} {subnet1}"
    if verbose: print(command)
    s2.execute(command, quiet=(not verbose))
    
    command = f'sudo ip -6 addr del {h23_ipv6_old} dev {ifaces["h23"].get_device_name()}'
    if verbose: print(command)
    h23.execute(command, quiet=(not verbose))
    
    command = f'sudo ip -6 addr add {h23_ipv6} dev {ifaces["h23"].get_device_name()}'
    if verbose: print(command)
    h23.execute(command, quiet=(not verbose))
    ips['h23'] = h23_ipv6
    
    command = f'sudo ip -6 route replace {h23_ipv6} via {gateways["h23"][0]}'
    if verbose: print(command)
    h23.execute(command, quiet=(not verbose))
    
    for destname, dest in hosts.items():
        if destname == "h23": continue
        command = f'sudo ip -6 route replace {h23_ipv6} via {gateways[destname][0]}'
        if verbose: print(command)
        dest.execute(command, quiet=(not verbose))
    #command = f'sudo ip -6 route del {subnet2} && sudo ip -6 route del {subnet1}'
    #if verbose: print(command)
    #stdout, stderr = h23.execute(command, quiet=(not verbose))
    #if verbose: print(f'sudo ifconfig {h23_iface_name} add {h23_ipv6} up && sudo ip -6 route add {subnet2} dev {h23_iface_name} && sudo ip -6 route add {subnet1} dev {h23_iface_name}')
    #stdout, stderr = h23.execute(f'sudo ifconfig {h23_iface_name} add {h23_ipv6} up && sudo ip -6 route add {subnet2} dev {h23_iface_name} && sudo ip -6 route add {subnet1} dev {h23_iface_name}', quiet=(not verbose))
    # for destname, dest in hosts.items():
    #     if destname == "h23": continue
    #     if verbose: print(f'h23:sudo ip -6 neigh del {ips[destname]} dev {h23_iface_name}')
    #     stdout, stderr = h23.execute(f'sudo ip -6 neigh del {ips[destname]} dev {h23_iface_name}', quiet=(not verbose))
    #     if verbose: print(f'h23:sudo ip -6 neigh add {ips[destname]} lladdr {s2_macs[3]} dev {h23_iface_name}')
    #     stdout, stderr = h23.execute(f'sudo ip -6 neigh add {ips[destname]} lladdr {s2_macs[3]} dev {h23_iface_name}', quiet=(not verbose))
    #     if verbose: print(f'{destname}:sudo ip -6 neigh del {h23_ipv6_old} dev {ifaces[destname]}')
    #     stdout, stderr = dest.execute(f'sudo ip -6 neigh del {h23_ipv6_old} dev {ifaces[destname]}', quiet=(not verbose))
    #     if verbose: print(f'{destname}:sudo ip -6 neigh add {h23_ipv6} lladdr {nhop_macs[destname]} dev {ifaces[destname]}')
    #     stdout, stderr = dest.execute(f'sudo ip -6 neigh add {h23_ipv6} lladdr {nhop_macs[destname]} dev {ifaces[destname]}', quiet=(not verbose))
        
    counter = 0
    for destname, dest in hosts.items():
        if destname == "h23": continue
        if h23.ping_test(ips[destname]):
            counter += 1
        else:
            print(f"h23 failed to ping {destname}")
    h23score = 0
    if counter == 5:
        print(f"h23 5/5 pings successful, +2.5pts")
        h23score = 2.5
    else:
        print(f"h23 {counter}/5 pings successful, 0pts")
    return h23score