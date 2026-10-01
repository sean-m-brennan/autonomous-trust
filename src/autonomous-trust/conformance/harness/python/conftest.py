# ******************
#  Copyright 2026 TekFive, Inc., Sean M. Brennan, and contributors
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
"""The verification layers' distribution on sys.path for a checkout run.

The physics, calibration, certificate, prequential and replication adapters
drive ``autonomous_trust.oracle`` (src/autonomous-trust-oracle,
FEATURE_SPLIT_PLAN Phase 3), a sibling of this package. An install has it
already; a source tree needs it put beside the core, as the sibling
distributions' own conftests do for the core. A conformance plug-in
($AT_CONFORMANCE_PLUGINS, runner.py) puts its own distribution on the path.
"""
import os
import sys

# ZTA (src/autonomous-trust-zta, FEATURE_SPLIT_PLAN Phase 6) likewise: the
# identity adapter's zta_policy scenarios run with it, as C's do with libat_zta,
# and skip without it.
for _dist in ('autonomous-trust-oracle', 'autonomous-trust-zta'):
    _dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..',
                                        '..', '..', _dist))
    if os.path.isdir(_dir) and _dir not in sys.path:
        sys.path.insert(0, _dir)
