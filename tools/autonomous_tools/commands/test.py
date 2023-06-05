import os
import random
import subprocess
import time

from ..config import images, packages
from ..docker.build import build_containers
from ..docker.network import create_network
from ..docker.run import run_container, run_interactive_container


def test(num_nodes: int = 4, debug: bool = False, tunnel: bool = False, force: bool = False):
    debug_build = debug == 'all' or debug == 'build'
    for pkg_name, path in packages.items():
        build_containers(pkg_name, 'devel', debug=debug_build, force=force)
        build_containers(pkg_name, 'test', debug=debug_build, force=force)

    create_network(with_host=True, force=force)

    min_sec = 1
    max_sec = 5
    for _, path in packages.items():
        containers = ''
        ip_file = os.path.join(path, 'docker_ips')
        with open(ip_file, 'a') as ip_list:
            for n in range(1, num_nodes + 1):
                ident = 'at-%d' % n
                containers += ' ' + ident
                run_container(ident, 'autonomous-trust', 'at-net')
                fmt = '{{range.NetworkSettings.Networks}}{{.IPAddress}}{{end}}'
                ip = subprocess.getoutput("docker inspect --format '%s' %s" % (fmt, ident))
                ip_list.write(ip + '\n')
                time.sleep(random.randint(min_sec, max_sec))
        time.sleep(1)
        run_interactive_container('at-test', 'autonomous-trust-test', 'at-net', mounts=[(path, '/app')],
                                  debug_run=debug, tunnel=tunnel, blocking=True)
        # tests complete # FIXME not blocking
        subprocess.call(('docker stop' + containers).split())
        os.remove(ip_file)
