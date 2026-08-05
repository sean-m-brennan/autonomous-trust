# ******************
#  Copyright 2023 TekFive, Inc., Sean M. Brennan, and contributors
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

import pytest

import autonomous_trust
from autonomous_trust.core.network.ping_at import ping_at

here = autonomous_trust.__file__
if here is None:
    here = '/app/autonomous_trust/__init__.py'
host_dir = os.path.abspath(os.path.join(os.path.dirname(here), '..'))

docker_ips_path = os.path.join(host_dir, 'docker_ips')


@pytest.mark.skipif(not os.path.exists(docker_ips_path),
                    reason='docker_ips not found (Docker-only test)')
def test_peer_ping():
    with open(docker_ips_path, 'r') as ip:
        for line in ip:
            ip_address = line.strip()
            stats = ping_at(ip_address)
            print(stats)
