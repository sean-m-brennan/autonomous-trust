import os
import autonomous_trust
from autonomous_trust.core.network.ping import ping

host_dir = os.path.abspath(os.path.join(os.path.dirname(autonomous_trust.__file__), '..'))


def test_peer_ping():
    with open(os.path.join(host_dir, 'docker_ips'), 'a') as ip:
        for line in ip:
            ip_address = line.strip()
            stats = ping(ip_address)
            print(stats)