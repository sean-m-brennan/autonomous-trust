import subprocess

from ..config import network_type, network_name, ipv4_subnet as docker_ip4_subnet, ipv6_subnet as docker_ip6_subnet
from ..config import multicast, ipv6, macvlan_bridge
from ..util import sudo_command


def get_default_route_info():
    default_rt = subprocess.check_output(['ip', '-o', '-4', 'route', 'show', 'to', 'default']).decode().split('\n')[-2]
    gateway = default_rt.split()[2]
    device = default_rt.split()[4]
    host_ip = default_rt.split()[8]
    return gateway, host_ip, device


def setup_support_network(subnet_cidr=docker_ip4_subnet, iface=macvlan_bridge, device=None, force=False):
    # Configure docker network (needs iproute2mac on MacOS)
    pwd = None
    if force:
        pwd = remove_support_network(iface)
    if device is None:
        device = get_default_route_info()[-1]
    prefix = '.'.join(subnet_cidr.split('.')[:-1])
    mask = int(subnet_cidr.split('/')[-1])
    address = '%s.2' % prefix  # FIXME host addr?
    ip_range = '%s.3/%d' % (prefix, mask - 1)  # FIXME wrong
    pwd = sudo_command('ip link add %s link %s type macvlan mode bridge' % (iface, device), pwd)
    pwd = sudo_command('ip addr add %s/32 dev %s' % (address, iface), pwd)
    pwd = sudo_command('ip link set %s up' % iface, pwd)
    sudo_command('ip route add %s dev %s' % (ip_range, iface), pwd)  # FIXME Invalid prefix for given prefix length


def remove_support_network(iface=macvlan_bridge):
    if iface in subprocess.getoutput('ip link show'):
        return sudo_command('ip link delete %s' % iface)


def create_network(name=network_name, net_type=network_type, ip4_subnet=docker_ip4_subnet,
                   ip6_subnet=docker_ip6_subnet, with_mcast=multicast, with_ipv6=ipv6, with_host=False, force=False):
    present = False
    net_list = subprocess.check_output(['docker', 'network', 'ls']).decode().split('\n')
    for line in net_list:
        if line and name in line.split()[1]:
            present = True

    if not force and present:
        return
    if force and network_name in subprocess.getoutput('docker network list'):
        subprocess.check_call(['docker', 'network', 'rm', name])

    gateway, _, device = get_default_route_info()
    prefix = '.'.join(ip4_subnet.split('.')[:-1])
    mask = int(ip4_subnet.split('/')[-1])
    ip_range = '%s/%d' % (prefix + '.3', mask + 1)
    aux = prefix + '.130'
    unused = prefix + '.131'
    iface = name + '-bridge'

    print('Support network')
    if with_host and net_type == 'macvlan':
        setup_support_network(ip4_subnet, iface, device)
    else:
        remove_support_network(iface)

    options = ['--opt', 'parent=%s' % device, '--subnet', ip4_subnet, '--gateway', unused,
               '--ip-range', ip_range, '--aux-address', 'router=%s' % gateway]
    print('Base options %s' % options)
    if with_ipv6:
        options += ['--ipv6']
    if net_type == 'macvlan':
        options += ['-o', 'macvlan_mode=bridge']
    if with_host and net_type == 'macvlan':
        options += ['--aux-address', 'host=%s' % aux]

    cmd = ['docker', 'network', 'create']
    if with_mcast:
        subprocess.check_call(['docker', 'swarm', 'init'])
        subprocess.check_call(cmd + options + ['-driver=weaveworks/net-plugin:latest_release', '--attachable', name])
    else:
        subprocess.check_call(cmd + options + ['--driver', net_type, name])
