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
"""Modeling & simulation harnesses for SOW Task 2 performance-feasibility targets.

Pure, deterministic, dependency-free (stdlib only) so the figures reproduce
byte-for-byte under a fixed seed and run anywhere. See :mod:`.latency` for the
Latency-(-50%) target (SOW Task 2.4).
"""
from .latency import (LatencyConfig, LinkModel, LatencyResult,  # noqa: F401
                      PROFILES, run, sweep)
