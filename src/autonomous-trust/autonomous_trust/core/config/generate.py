import inspect
import os
import sys
import random
import re
import socket
import subprocess

from .configuration import Configuration, CfgIds, InitializableConfig
from .names import random_name
from ..processes import ProcessTracker
from ..network import Network, NetworkProtocol
from ..identity import Identity
from ..system import communications, core_system


_names = [
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


def _get_default_device():
    route = subprocess.check_output(['/sbin/ip', 'route']).decode().split('\n')[0]
    if 'default' in route:
        return route.split()[4]
    return route.split()[2]


def _get_addresses():
    device = _get_default_device()
    if device == '':
        device = 'eth0'
    ip4_address = None
    ip6_address = None
    result = subprocess.run(['/sbin/ip', '-o', 'a', 'show', device], shell=False,
                            capture_output=True, text=True, check=True)
    for line in result.stdout.split('\n'):
        if 'inet ' in line:
            ip4_address = line.split()[3]
        elif 'inet6' in line:
            ip6_address = line.split()[3]
    result = subprocess.run(['/sbin/ip', '-o', 'l', 'show', device], shell=False,
                            capture_output=True, text=True, check=True)
    hex_pattern = r'[0-9a-f][0-9a-f]'
    mac_pattern = r'{hex}:{hex}:{hex}:{hex}:{hex}:{hex}'.format(hex=hex_pattern)
    match = re.search(r'link/ether (%s)' % mac_pattern, result.stdout)
    mac_address = match.group(1)

    return ip4_address, ip6_address, mac_address


def _subsystems(net_impl):
    pt = ProcessTracker()
    for name, impl in core_system.items():
        if name == CfgIds.network:
            pt.register_subsystem(name, net_impl)
        else:
            pt.register_subsystem(name, impl)
    return pt


def generate_identity(cfg_dir, randomize=False, seed=None, silent=True, preserve=False, defaults=False, peers=False):
    if seed is not None:
        try:
            seed = int(seed)
        except ValueError:
            seed = sum([ord(x) for x in seed])

    ident_file = os.path.join(cfg_dir, CfgIds.identity + Configuration.yaml_file_ext)
    net_file = os.path.join(cfg_dir, CfgIds.network + Configuration.yaml_file_ext)
    sub_sys_file = os.path.join(cfg_dir, ProcessTracker.default_filename)

    unqualified_hostname = socket.gethostname()
    hostname = socket.getfqdn(unqualified_hostname)
    if hostname == 'localhost':
        hostname = unqualified_hostname
    ip4_address, ip6_address, mac_address = _get_addresses()  # TODO multi-device

    mod, cls = communications.rsplit('.', 1)
    proto_cls = getattr(sys.modules[mod], cls)
    address = None
    if proto_cls.net_proto == NetworkProtocol.IPV4:
        address = ip4_address.split('/')[0]
    elif proto_cls.net_proto == NetworkProtocol.IPV6:
        address = ip6_address.split('/')[0]
    elif proto_cls.net_proto == NetworkProtocol.MAC:
        address = mac_address

    if randomize:
        if seed is None:
            seed = random.randint(1, 254)
        # Assume we're running in docker or kvm, so queried addresses work
        idx = seed % len(_names)
        fullname = _names[idx]
        nickname = fullname.split('@')[0].rsplit('.', 1)[1]
        net_cfg = Network.initialize(ip4_address, ip6_address, mac_address)
        ident_cfg = Identity.initialize(fullname, nickname, address)
        sub_sys_cfg = _subsystems(communications)
        if not os.path.exists(net_file):
            net_cfg.to_file(net_file)
        if not os.path.exists(ident_file):
            ident_cfg.to_file(ident_file)
        if not os.path.exists(sub_sys_file):
            sub_sys_cfg.to_file(sub_sys_file)
        if not silent:
            print('Wrote configs to %s' % cfg_dir)
        return net_cfg, ident_cfg, sub_sys_cfg

    if not preserve:
        print('Configuring an AutonomousTrust identity')
    if not os.path.exists(ident_file) or not preserve:
        try:
            fullname = input('  Fullname (FQDN) [%s]: ' % hostname)
            if fullname == '':
                fullname = hostname
            nickname = input('  Nickname: ')
        except EOFError:
            fullname = hostname
            nickname = random_name(sep='', cap=True)
    if not os.path.exists(net_file) or not preserve:
        if defaults:
            ip4_addr = ip4_address
            ip6_addr = ip6_address
            mac_addr = mac_address
        else:
            ip4_addr = input('  IP4 address [%s]: ' % ip4_address)
            if ip4_addr == '':
                ip4_addr = ip4_address
            ip6_addr = input('  IP6 address [%s]: ' % ip6_address)
            if ip6_addr == '':
                ip6_addr = ip6_address
            mac_addr = input('  MAC address [%s]: ' % mac_address)
            if mac_addr == '':
                mac_addr = mac_address
    if not os.path.exists(sub_sys_file) or not preserve:
        try:
            net_impl = input('  Network Implementation [%s]: ' % communications)
        except EOFError:
            net_impl = ''
        if net_impl == '':
            net_impl = communications

    sub_sys_cfg = None
    if not os.path.exists(net_file) or not preserve:
        net_cfg = Network.initialize(ip4_addr, ip6_addr, mac_addr)  # noqa
    else:
        net_cfg = Network.from_file(net_file)
    if not os.path.exists(ident_file) or not preserve:
        ident_cfg = Identity.initialize(fullname, nickname, net_cfg.ip4)  # noqa
    else:
        ident_cfg = Identity.from_file(ident_file)
    if not os.path.exists(sub_sys_file) or not preserve:
        sub_sys_cfg = _subsystems(net_impl)  # noqa

    for cfg_name, cfg_file, cfg in (('network', net_file, net_cfg),
                                    ('identity', ident_file, ident_cfg),
                                    ('subsystem', sub_sys_file, sub_sys_cfg)):
        if not os.path.exists(cfg_file) or not preserve:
            overwrite = True
            if os.path.exists(cfg_file):
                overwrite = False
                if input('    Write %s config to %s [y/N] ' % (cfg_name, cfg_file)).lower().startswith('y'):
                    overwrite = True
            if overwrite:
                cfg.to_file(cfg_file)
                print('%s config written to %s' % (cfg_name.capitalize(), cfg_file))

    return net_cfg, ident_cfg, sub_sys_cfg


def random_config(base_dir, ident: str = None):
    if Configuration.VARIABLE_NAME in os.environ:
        cfg_dir = Configuration.get_cfg_dir()
    else:
        cfg_dir = os.path.join(base_dir, Configuration.CFG_PATH)
        if ident is not None:
            cfg_dir = os.path.join(base_dir, ident, Configuration.CFG_PATH)
    if not os.path.isdir(cfg_dir):
        os.makedirs(cfg_dir, exist_ok=True)
        generate_identity(cfg_dir, randomize=True, seed=ident)
    os.environ[Configuration.VARIABLE_NAME] = cfg_dir


def generate_worker_config(cfg_dir: str, proc_name: str, cfg_class: type[InitializableConfig], defaults: bool = False):
    cfg_file = os.path.join(cfg_dir, proc_name + Configuration.yaml_file_ext)
    if not os.path.exists(cfg_file):
        print('Configure %s --' % proc_name)
        spec = inspect.getfullargspec(cfg_class.initialize)
        ann = inspect.get_annotations(cfg_class.initialize)
        arg_names = spec[0][1:]
        defaults_list = spec[3]
        default_values = {}
        if defaults_list is not None:
            for idx, name in enumerate(arg_names[-len(defaults_list):]):
                default_values[name] = defaults_list[idx]

        args = []
        for idx, name in enumerate(arg_names):
            if name in default_values:
                if defaults:
                    arg = default_values[name]
                else:
                    arg = input('  %s [%s]: ' % (name, default_values[name]))
                    if arg == '':
                        arg = default_values[name]  # type is correct here
            else:
                arg = input('  %s: ' % name)
            if name in ann:
                arg = ann[name](arg)
            args.append(arg)

        cfg_obj = cfg_class.initialize(*args)
        if cfg_obj is not None:
            cfg_obj.to_file(cfg_file)
