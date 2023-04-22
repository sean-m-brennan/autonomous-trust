import os
import random
import socket
import uuid

from .reputation import ReputationProcess
from .processes import ProcessTracker
from .identity.identity import Identity
from .identity.idprocess import IdentityProcess
from .network import *
from .configuration import Configuration


names = [
    'j.h.watson@tekfive.com',
    'a.hastings@tekfive.com',
    'a.goodwin@tekfive.com',
    'j.may@tekfive.com',
    'a.bryant@tekfive.com',
    't.beresford@tekfive.com',
    'n.charles@tekfive.com',
    'd.selby@tekfive.com',
    'm.archer@tekfive.com',
    'r.lewis@tekfive.com',
]


def get_mac_address(number=uuid.getnode()):
    mac_hex = '{:012x}'.format(number)
    return ':'.join(mac_hex[i:i+2] for i in range(0, len(mac_hex), 2))


def write_subsystems(net_impl, sub_sys_file):
    pt = ProcessTracker()
    pt.register_subsystem(NetworkProcess.cfg_name, net_impl)
    pt.register_subsystem(IdentityProcess.cfg_name,
                          IdentityProcess.__module__ + '.' + IdentityProcess.__qualname__)
    pt.register_subsystem(ReputationProcess.cfg_name,
                          ReputationProcess.__module__ + '.' + ReputationProcess.__qualname__)
    pt.to_file(sub_sys_file)


def generate_identity(cfg_dir, randomize=False, seed=None):
    if seed is not None:
        try:
            seed = int(seed)
        except ValueError:
            seed = sum([ord(x) for x in seed])

    ident_file = os.path.join(cfg_dir, IdentityProcess.cfg_name + Configuration.yaml_file_ext)
    net_file = os.path.join(cfg_dir, NetworkProcess.cfg_name + Configuration.yaml_file_ext)
    sub_sys_file = os.path.join(cfg_dir, ProcessTracker.default_filename)

    unqualified_hostname = socket.gethostname()
    hostname = socket.getfqdn(unqualified_hostname)
    if hostname == 'localhost':
        hostname = unqualified_hostname
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.connect(("8.8.8.8", 80))
        ip_address = sock.getsockname()[0]
    if ip_address == '0.0.0.0':
        ip_address = socket.gethostbyname(hostname)
    mac_address = get_mac_address()
    protocol = SimpleTCPNetworkProcess.__module__ + '.' + SimpleTCPNetworkProcess.__qualname__

    if randomize:
        if seed is None:
            seed = random.randint(1, 254)
        # Assume we're running in docker, so queried addresses work
        idx = seed % len(names)
        fullname = names[idx]
        nickname = fullname.split('@')[0].rsplit('.', 1)[1]
        net_impl = protocol
        Identity.initialize(fullname, nickname, ip_address).to_file(ident_file)
        Network.initialize(ip_address, mac_address).to_file(net_file)
        write_subsystems(net_impl, sub_sys_file)
        return

    print('Configuring an AutonomousTrust identity')
    fullname = input('  Fullname (FQDN) [%s]: ' % hostname)
    if fullname == '':
        fullname = hostname
    nickname = input('  Nickname: ')
    ip_addr = input('  IP address [%s]: ' % ip_address)
    if ip_addr == '':
        ip_addr = ip_address
    mac_addr = input('  MAC address [%s]: ' % mac_address)
    if mac_addr == '':
        mac_addr = mac_address
    net_impl = input('  Network Implementation [%s]: ' % protocol)
    if net_impl == '':
        net_impl = protocol

    overwrite = True
    if os.path.exists(ident_file):
        overwrite = False
        if input('    Write identity to %s [y/N] ' % ident_file).lower().startswith('y'):
            overwrite = True
    if overwrite:
        Identity.initialize(fullname, nickname, ip_addr).to_file(ident_file)
        print('Identity config written to %s' % ident_file)
    overwrite = True
    if os.path.exists(net_file):
        overwrite = False
        if input('    Write network config to %s [y/N] ' % net_file).lower().startswith('y'):
            overwrite = True
    if overwrite:
        Network.initialize(ip_addr, mac_addr).to_file(net_file)
        print('Network config written to %s' % net_file)
    if os.path.exists(sub_sys_file):
        overwrite = False
        if input('    Write subsystem config to %s [y/N] ' % sub_sys_file).lower().startswith('y'):
            overwrite = True
    if overwrite:
        write_subsystems(net_impl, sub_sys_file)
        print('Subsystems config written to %s' % sub_sys_file)
