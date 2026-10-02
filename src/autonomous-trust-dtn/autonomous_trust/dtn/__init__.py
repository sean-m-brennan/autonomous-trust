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
"""DTN / Bundle Protocol (FEATURE_SPLIT_PLAN Phase 9), as a distribution
separate from the core: AT over a Bundle Protocol agent, for links that are
disconnected more often than not.

Laid out as the core is, ``_python`` beside ``_native`` (FEATURE_SPLIT_PLAN D2),
so ``autonomous_trust.dtn.transport`` resolves through the core's backend
redirector. The native side is empty: a node's network process is Python on
either backend, and the C twin is its own library (``libat_dtn``,
src/c/extensions/dtn/), which the native loader dlopens beside the core.

Importing it changes nothing. A node uses it by naming the transport
(``AT_TRANSPORT=autonomous_trust.dtn.transport.DTNNetworkProcess``), or as the
``dtn_bp`` leg of the core's hybrid transport; ``AT_DTN_BACKEND`` picks the BP
agent (``stub`` or ``ud3tnv2``).
"""
from autonomous_trust.core import register_backend_prefix

register_backend_prefix('autonomous_trust.dtn.')
