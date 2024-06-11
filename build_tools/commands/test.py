# ******************
#  Copyright 2024 TekFive, Inc. and contributors
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.
# ******************

import os
import random
import subprocess
import time
from pathlib import Path

from ..config import packages, sources
from ..docker.build import build_containers
from ..docker.network import create_network, get_default_route_info
from ..docker.run import run_container, run_interactive_container


def test(num_nodes: int = 4, debug: bool = False, tunnel: bool = False, force: bool = False, quick=False, shell=False):
    debug_build = debug == 'all' or debug == 'build'
    debug_run = debug == 'all' or debug == 'run'
    if not quick:
        build_containers(which='devel', debug=debug_build, force=force)
        build_containers(which='test', debug=debug_build, force=force)

    create_network(force=force)  # host not needed for these tests
    gateway = get_default_route_info()[0]

    mount_targets = ['tests', 'coverage', 'tox.ini', 'requirements.txt', 'tests_require.txt', 'docker_ips']

    min_sec = 1
    max_sec = 5
    extras = ['-e', 'ROUTER=%s' % gateway, '-e', 'AUTONOMOUS_TRUST_ARGS="--live --test"']
    for pkg, path in packages.items():
        ip_file = os.path.join(path, 'docker_ips')
        Path(ip_file).touch()
        os.makedirs(os.path.join(path, 'coverage'), exist_ok=True)

        mounts = []
        for mnt in mount_targets:
            mounts += [(os.path.join(path, mnt), os.path.join('/app', mnt))]
        for base, src in sources[pkg]:
            mounts += [(os.path.join(base, src), os.path.join('/app', src))]

        containers = ''
        for n in range(1, num_nodes + 1):
            ident = 'at-%d' % n
            containers += ' ' + ident
            if debug_run:
                run_interactive_container(ident, 'autonomous-trust', 'at-net',
                                          net_admin=True, extra_args=extras, tunnel=tunnel)
            else:
                run_container(ident, 'autonomous-trust', 'at-net', net_admin=True, extra_args=extras)
            time.sleep(random.randint(min_sec, max_sec))
        time.sleep(1)
        with open(ip_file, 'a') as ip_list:
            for n in range(1, num_nodes + 1):
                ident = 'at-%d' % n
                fmt = '{{range.NetworkSettings.Networks}}{{.IPAddress}}{{end}}'
                ip = subprocess.getoutput("docker inspect --format '%s' %s" % (fmt, ident))
                ip_list.write(ip + '\n')
        run_interactive_container('at-test', 'autonomous-trust-test', 'at-net', mounts=mounts, extra_args=extras,
                                  net_admin=True, debug_run=debug_run, tunnel=tunnel, blocking=True, override=shell)
        # tests complete
        subprocess.call(('docker stop' + containers).split())
        os.remove(ip_file)
        time.sleep(2)
