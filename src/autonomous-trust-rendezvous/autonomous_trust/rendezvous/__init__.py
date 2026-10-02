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
"""Rendezvous (FEATURE_SPLIT_PLAN Phase 7b), as a distribution separate from the
core: the relay client and server, signed reachability records, the seed list
and community rosters, and the network process's relay routes. First contact
rides it.

Laid out as the core is, ``_python`` beside ``_native`` (FEATURE_SPLIT_PLAN D2),
so ``autonomous_trust.rendezvous.relay`` resolves through the core's backend
redirector. The native side is empty: the C twin is its own library
(``libat_rendezvous``, src/c/extensions/rendezvous/), and this package is pure
Python on either backend.

Importing it changes nothing. The core finds it through ``_at_extension.py``
(a source tree) or the ``autonomous_trust.extensions`` entry point (an
install). ``AT_USE_RELAY`` registers with relays, ``AT_RELAY`` serves as one,
and ``AT_RELAY_SEED_FALLBACK`` lets the rosters and the seed list stand in for
``AT_USE_RELAY``.
"""
from autonomous_trust.core import register_backend_prefix

register_backend_prefix('autonomous_trust.rendezvous.')
