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

from autonomous_trust.core.system import default_comm_port

from ..conftest import QuickTrust, Configuration


def run_nominal(mp=True, debug=False, runtime=None, base_port=None):
    # Each nominal run gets its own base port. Both run on the same address
    # (setup_local_net_teardown -> 127.0.0.1) back to back, and the previous run's
    # PingAT socket (base+2) can still be held when the next one binds -- AT refuses
    # that bind by design (no SO_REUSEADDR on unicast recv sockets,
    # doc/architecture/networking.md), so sharing a base port makes the pair depend on
    # shutdown timing. Distinct ports is the framework's own advice for co-located
    # nodes.
    if base_port is not None:
        os.environ['AT_COMM_PORT'] = str(base_port)
    at = QuickTrust(runtime=runtime, multiproc=mp, logfile=Configuration.log_stdout)
    at.debug = debug
    at.run_forever()
    return at


######################
# Tests:

def test_multiproc_nominal(setup_local_net_teardown):
    at = run_nominal(True, base_port=default_comm_port + 20)
    assert len(at.exceptions) == 0


def test_threading_nominal(setup_local_net_teardown):
    at = run_nominal(False, base_port=default_comm_port + 40)
    assert len(at.exceptions) == 0

# FIXME test pathologies
