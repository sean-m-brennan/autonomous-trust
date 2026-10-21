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
"""Replicated execution (R+D.md §12.6) has no scorer arm yet -- nothing in the
scoring path calls it -- so it only declares itself (``..oracles``), which is
what lets a node say it has the layer. The Python twin of
``replication_oracle.c``.
"""
from autonomous_trust.core import oracles

oracles.declare('replication')
