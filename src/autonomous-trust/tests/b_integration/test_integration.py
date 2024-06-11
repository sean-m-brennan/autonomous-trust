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

from ..conftest import QuickTrust, Configuration


def run_nominal(mp=True, debug=False, runtime=None):
    at = QuickTrust(runtime=runtime, multiproc=mp, logfile=Configuration.log_stdout)
    at.debug = debug
    at.run_forever()
    return at


######################
# Tests:

def test_multiproc_nominal(setup_local_net_teardown):
    at = run_nominal(True)
    assert len(at.exceptions) == 0


def test_threading_nominal(setup_local_net_teardown):
    at = run_nominal(False)
    assert len(at.exceptions) == 0

# FIXME test pathologies
