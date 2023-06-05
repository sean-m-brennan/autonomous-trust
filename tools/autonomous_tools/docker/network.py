import getpass
import subprocess

from ..config import network_type, network_name, ipv4_subnet as docker_ip4_subnet, ipv6_subnet as docker_ip6_subnet
from ..config import multicast, ipv6, macvlan_bridge


def get_default_route_info():
    default_rt = subprocess.check_output(['ip', '-o', '-4', 'route', 'show', 'to', 'default']).decode().split('\n')[-2]
    gateway = default_rt.split()[2]
    host_ip = default_rt.split()[4]
    device = default_rt.split()[8]
    return gateway, host_ip, device


def sudo_command(cmd, pwd=None, echo=False):
    import pexpect
    if not isinstance(cmd, str):
        cmd = ' '.join(cmd)
    proc = pexpect.spawn('sudo ' + cmd)
    if proc.expect(['(?i)password.*']) == 0:
        if pwd is None:
            pwd = getpass.getpass('[sudo] Administrative password: ')
        proc.sendline(pwd)
    proc.expect([pexpect.EOF, pexpect.TIMEOUT], timeout=1)
    if proc.exitstatus != 0:
        raise RuntimeError('sudo command failed: %d' % proc.exitstatus)
    out = proc.before.decode()
    if echo:
        print(out)
    return pwd


def setup_support_network(subnet_cidr=docker_ip4_subnet, device=None):
    # Configure docker network (needs iproute2mac on MacOS)
    if device is None:
        device = get_default_route_info()[-1]
    prefix = '.'.join(subnet_cidr.split('.')[:-1])
    mask = int(subnet_cidr.split('/')[-1])
    address = '%s.2' % prefix
    ip_range = '%s.3/%d' % (prefix, mask)
    pwd = sudo_command('ip link add %s link %s type macvlan mode bridge' % (macvlan_bridge, device))
    pwd = sudo_command('ip addr add %s/32 dev %s' % (address, macvlan_bridge), pwd)
    pwd = sudo_command('ip link set %s up' % macvlan_bridge, pwd)
    sudo_command('ip route add %s dev %s' % (ip_range, macvlan_bridge), pwd)


def remove_support_network(iface):
    link_list = subprocess.check_output(['ip', 'link', 'show']).decode().split('\n')
    if iface in link_list:
        sudo_command('ip link delete %s' % iface)


def create_network(name=network_name, net_type=network_type, ip4_subnet=docker_ip4_subnet,
                   ip6_subnet=docker_ip6_subnet, with_mcast=multicast, with_ipv6=ipv6, with_host=False, force=False):
    present = False
    net_list = subprocess.check_output(['docker', 'network', 'ls']).decode().split('\n')
    for line in net_list:
        if line and name in line.split()[1]:
            present = True

    if not force and present:
        return
    if force:
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
        setup_support_network(ip4_subnet, device)
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
