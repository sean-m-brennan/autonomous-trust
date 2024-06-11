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

import random
import time

from ..config import image_name, network_name
from .network import create_network, get_default_route_info
from .build import build_containers
from .run import run_interactive_container

remote_port = 2357


class DbgModes(object):
    all = 'all'
    build = 'build'
    run = 'run'
    remote = 'remote'


def emulate(num_nodes: int = 2, force: bool = False, debug: DbgModes = None, excludes=('network',),
            tunnel: bool = False, devel: bool = False, quick: bool = False, shell: bool = False):
    if not quick:
        build_containers('packaged')  # FIXME conditional build not working
    create_network(force=force)

    gateway, remote_ip, _ = get_default_route_info()
    remote = '%s:%s' % (remote_ip, remote_port)
    min_sec = 1
    max_sec = 5

    exclude_args = ''
    for cls in excludes:
        exclude_args += '--exclude-logs %s' % cls

    extras = ['-e', 'ROUTER=%s' % gateway, '--cap-add', 'NET_ADMIN']
    img_name = image_name
    if devel:
        img_name += '-devel'
    mounts = []

    for n in range(1, num_nodes+1):
        remote_dbg = ''
        if debug in [DbgModes.all, DbgModes.remote] and n == 1:
            remote_dbg = '--remote-debug %s' % remote
        debug_run = debug in [DbgModes.all, DbgModes.run]
        extra_args = extras + ['-e', 'AUTONOMOUS_TRUST_ARGS="--live --test %s %s"' % (remote_dbg, exclude_args)]
        name = 'at-%s' % n

        run_interactive_container(name, img_name, network_name, mounts=mounts, extra_args=extra_args,
                                  debug_run=debug_run, tunnel=tunnel, override=shell)
        if n < num_nodes:
            time.sleep(random.randint(min_sec, max_sec))
