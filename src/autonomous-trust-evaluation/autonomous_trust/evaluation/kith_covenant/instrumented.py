# ******************
#  Copyright 2025 Sean M. Brennan and contributors
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

"""Instrumented AT node with both MetricsCollector and KithCovenantObserver."""

from autonomous_trust.evaluation.instrumented import InstrumentedAT
from autonomous_trust.evaluation.kith_covenant.observer import KithCovenantObserver


class KithCovenantInstrumentedAT(InstrumentedAT):
    """AT node that tees messages to both MetricsCollector and KithCovenantObserver."""

    _kith_covenant_policy = None
    _kith_covenant_output = None

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if self._kith_covenant_policy:
            self.add_worker(KithCovenantObserver,
                            policy=self._kith_covenant_policy,
                            output_path=self._kith_covenant_output)
