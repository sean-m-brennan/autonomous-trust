import os
import sys
import platform

ARCH = platform.machine()
OS = sys.platform

default_cpu_count = os.cpu_count()
default_initrd_fs = False

conda_home = os.path.join(os.path.expanduser('~'), '.miniconda3')

qemu_user_prefix = '/opt/qemu-user-static'

supported_platforms = ['linux/amd64', 'linux/arm64']

image_name = "autonomous-trust"

network_name = "at-net"
network_type = "macvlan"
macvlan_bridge = 'macvlan-bridge'
ipv4_subnet = '172.27.3.0/24'
ipv6_subnet = None
multicast = False
ipv6 = False


##############################
# Constants
conda_environ_name = 'autonomous_trust'
base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', '..'))
packages = {'autonomous_trust': os.path.join(base_dir, 'src', 'autonomous-trust'),
            'autonomous_trust.inspector': os.path.join(base_dir, 'src', 'autonomous-trust-inspector')}
images = {k: v.split('/')[-1] for k, v in packages.items()}

if OS == 'Linux':
    for path in ['/usr/bin/qemu-system-' + ARCH, '/usr/libexec/qemu-kvm']:
        if os.path.exists(path):
            qemu_system = path
            break
qemu_system = None
