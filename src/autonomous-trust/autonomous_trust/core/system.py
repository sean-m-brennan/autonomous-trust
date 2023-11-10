import multiprocessing
import os
import pkgutil
import queue
import sys
from traceback import print_tb
from datetime import datetime
from typing import Union

from nacl.hash import blake2b

from .algorithms.impl import AgreementImpl
from .util import ClassEnumMeta

pkg = __name__.rsplit('.', 1)[0]


class CfgIds(object, metaclass=ClassEnumMeta):
    main = 'main'
    network = 'network'
    identity = 'identity'
    peers = 'peers'
    capabilities = 'peer-capabilities'
    group = 'group'
    negotiation = 'negotiation'
    reputation = 'reputation'


# Constants for system tweaking
# communications = pkg + '.network.TCPNetworkProcess'  # FIXME not working
communications = pkg + '.network.UDPNetworkProcess'
comm_port = 27787
ping_rcv_port = comm_port + 2
ping_snd_port = ping_rcv_port + 1
ntp_port = comm_port + 4
preferred_proto_ver = 4
net_cadence = 0.0001
encoding = 'utf-8'  # FIXME hex?
cadence = 0.5
queue_cadence = 0.01
agreement_impl = AgreementImpl.POA.value
dev_root_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
core_system = {CfgIds.network: communications,
               CfgIds.identity: pkg + '.identity.IdentityProcess',
               CfgIds.negotiation: pkg + '.negotiation.NegotiationProcess',
               CfgIds.reputation: pkg + '.reputation.ReputationProcess',
               }
max_concurrency = os.cpu_count() * 2
base_system_deps = core_system.keys()


QueueType = Union[queue.Queue, multiprocessing.Queue]


def now():  # FIXME NTP sourced
    return datetime.utcnow()


class PackageHash(object):
    key = 'package_hash'
    excludes = ['viz']

    def __init__(self, pkg_path=None, pkg_name=None, debug=False):
        self.debug = debug
        self.modules = {}
        if pkg_path is None or pkg_name is None:
            package = sys.modules[__name__.split('.')[0]]
            if pkg_path is None:
                pkg_path = package.__path__
            if pkg_name is None:
                pkg_name = package.__name__
        for loader, name, is_pkg in pkgutil.walk_packages(pkg_path, pkg_name + '.'):
            for ex in self.excludes:
                if name.endswith('.' + ex) or '.%s.' % ex in name:
                    continue
            try:
                module_path = loader.find_spec(name).origin
                with open(module_path, 'r') as src:
                    source = src.read()
                module_hash = blake2b(source.encode(encoding))
                self.modules[name] = module_hash
            except (OSError, TypeError):
                if self.debug:
                    print('Skipping ', name)
        self.digest = blake2b(b''.join([dig for dig in self.modules.values()]))

    def onerror(self, name):
        if self.debug:
            print("Error importing module %s" % name)
            print_tb(sys.exc_info()[2])
