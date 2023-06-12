import os
import autonomous_trust
from autonomous_trust.core.network.ping import ping

here = autonomous_trust.__file__
if here is None:
    here = '/app/autonomous_trust/__init__.py'
host_dir = os.path.abspath(os.path.join(os.path.dirname(here), '..'))


def test_peer_ping():
    with open(os.path.join(host_dir, 'docker_ips'), 'r') as ip:
        for line in ip:
            ip_address = line.strip()
            stats = ping(ip_address)
            print(stats)
