import subprocess

from .. import config
from ..util import sudo_command


def configuration():
    router, _, device = get_default_route_info()
    prefix = '.'.join(config.ipv4_subnet.split('.')[:-1])
    mask = int(config.ipv4_subnet.split('/')[-1])
    ip_range = '%s/%d' % (prefix + '.132', mask + 1)
    aux = prefix + '.130'
    gateway = prefix + '.131'
    iface = config.network_name + '-bridge'
    return router, device, ip_range, aux, gateway, iface


def get_default_route_info():
    routes = subprocess.check_output(['ip', '-o', '-4', 'route', 'show']).decode().split('\n')
    gateway = routes[0].split()[2]
    device = routes[0].split()[4]
    for rt in routes:
        if device in rt and len(rt.split()) > 8 and rt.split()[7] == 'src':
            host_ip = rt.split()[8]
            return gateway, host_ip, device


def setup_support_network(subnet_cidr=config.ipv4_subnet, iface=config.macvlan_bridge, device=None, force=False):
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


def remove_support_network(iface=config.macvlan_bridge):
    if iface in subprocess.getoutput('ip link show'):
        return sudo_command('ip link delete %s' % iface)


def create_gwbridge(subnet=None, gateway=None, debug=False):
    name = 'docker_gwbridge'
    net_list = subprocess.check_output(['docker', 'network', 'ls']).decode().split('\n')
    for line in net_list:
        if line and name in line.split()[1]:
            try:
                subprocess.check_call(['docker', 'network', 'rm', name])
            except subprocess.CalledProcessError:
                pass  # ignore
            try:
                subprocess.check_call(['docker', 'network', 'prune', '-f'])
            except subprocess.CalledProcessError:
                pass  # ignore
    if subnet is None:
        subnet = config.ipv4_subnet
    if gateway is None:
        gateway = configuration()[4]
    options = ['--subnet', subnet,
               '--gateway', gateway,
               '-o com.docker.network.bridge.enable_icc=false',
               '-o com.docker.network.bridge.name=%s' % name,
               '-o com.docker.network.bridge.enable_ip_masquerade=true']
    cmd = ['docker', 'network', 'create'] + options + [name]
    if debug:
        print(' '.join(cmd))
    subprocess.check_call(cmd)


def network_options(net_type=config.network_type, ip4_subnet=config.ipv4_subnet,
                    ip6_subnet=config.ipv6_subnet, with_mcast=config.multicast, with_ipv6=config.ipv6,
                    with_host=False):
    router, device, ip_range, aux, gateway, iface = configuration()

    if with_host and net_type == 'macvlan':
        print('Support network')
        setup_support_network(ip4_subnet, iface, device)
    else:
        remove_support_network(iface)

    options = ['--opt', 'parent=%s' % device,
               '--subnet', ip4_subnet,
               '--gateway', gateway,
               '--ip-range', ip_range,
               '--aux-address', 'router=%s' % router]
    if with_ipv6:
        options += ['--ipv6']
    if net_type == 'macvlan':
        options += ['-o', 'macvlan_mode=bridge']
        if with_host:
            options += ['--aux-address', 'host=%s' % aux]

    return options


def create_network(name=config.network_name, net_type=config.network_type, ip4_subnet=config.ipv4_subnet,
                   ip6_subnet=config.ipv6_subnet, with_mcast=config.multicast, with_ipv6=config.ipv6,
                   with_host=False, force=False, swarm_scope=False, config_only=False, config_from=None,
                   debug=False):
    if name in subprocess.getoutput('docker network list'):
        if not force:
            return
        else:
            try:
                subprocess.check_call(['docker', 'network', 'rm', name])
            except subprocess.CalledProcessError:
                pass  # ignore
            try:
                subprocess.check_call(['docker', 'network', 'prune', '-f'])
            except subprocess.CalledProcessError:
                pass  # ignore

    options = []
    driver = []
    if config_from is None:
        options = network_options(net_type, ip4_subnet, ip6_subnet, with_mcast, with_ipv6, with_host)

    if config_only:
        options += ['--config-only']
    else:
        if config_from is not None:
            options += ['--config-from', config_from]
        if swarm_scope:
            options += ['--scope', 'swarm']

        driver = ['--driver', net_type]
        if with_mcast:
            driver = ['-driver=weaveworks/net-plugin:latest_release', '--attachable']

    cmd = ['docker', 'network', 'create'] + options + driver + [name]
    if debug:
        print(' '.join(cmd))
    subprocess.check_call(cmd)

    return cmd


def compose_config(version: int = 2, with_host: bool = False):
    router, device, ip_range, aux, gateway, iface = configuration()

    options = '    scope: swarm\n'
    if config.ipv6:  # not supported in swarm mode for compose ver 3
        options += "    enable_ipv6\n"
    aux_addr = ''
    if with_host and config.network_type == 'macvlan':
        aux_addr += "            host: %s\n" % aux
        setup_support_network(config.ipv4_subnet, iface, device)
    driver = "    driver: %s\n" % config.network_type
    if config.multicast:
        driver = "    driver: weaveworks/net-plugin:latest_release\n    attachable\n"
    if config.network_type == 'macvlan':
        driver += "    driver_opts:\n      o: \"macvlan_mode=bridge\"\n"

    if version == 2:
        return "networks:\n" + \
            "  %s:\n" % config.network_name + \
            options + \
            "    ipam:\n" + \
            "      driver: default\n" + \
            "      config:\n" + \
            "        - subnet: %s\n" % config.ipv4_subnet + \
            "          gateway: %s\n" % gateway + \
            "          ip_range: %s\n" % ip_range + \
            "          aux_addresses:\n" + \
            "            router: %s\n" % router + \
            aux_addr + \
            "      options:\n" + \
            "        parent: \"%s\"\n" % device + \
            driver + \
            "\n"
    else:  # version 3
        return "networks:\n" + \
            "  %s:\n" % config.network_name + \
            options + \
            driver + \
            "\n"
