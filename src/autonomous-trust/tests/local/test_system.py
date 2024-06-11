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

from autonomous_trust.core import LogLevel
from conftest import *


def run_library(mp=True, runtime=None):
    at = QuickTrust(runtime=runtime, multiproc=mp, log_level=LogLevel.DEBUG, logfile=Configuration.log_stdout)
    # FIXME extra functionality
    at.run_forever()  # blocks until timeout
    return at


def test_nominal(setup_teardown):
    at = run_library(True, 60)
    assert len(at.exceptions) == 0
    assert len(at.peers.all) == 4


def test_troubled(setup_teardown):
    at = run_library(True, 60)
    # FIXME pathologies here
    assert len(at.exceptions) == 0
