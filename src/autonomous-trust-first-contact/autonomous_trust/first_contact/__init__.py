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
"""First contact (FEATURE_SPLIT_PLAN Phase 7), as a distribution separate from
the core: contacts and invitations, the 1:1 handshake, the directory and area
flows, one human's devices and siblings, the backup, and the directory registry
and area hub a relay serves.

Laid out as the core is, ``_python`` beside ``_native`` (FEATURE_SPLIT_PLAN D2),
so ``autonomous_trust.first_contact.store`` resolves through the core's backend
redirector. The native side is empty: the C twin is its own library
(``libat_first_contact``, src/c/extensions/first_contact/), and this package is
pure Python on either backend.

Importing it changes nothing. The core finds it through ``_at_extension.py``
(a source tree) or the ``autonomous_trust.extensions`` entry points (an
install), and a node runs the handshake only when ``AT_FIRST_CONTACT`` is set.
Rendezvous, the relay it rides, is still the core's.
"""
from autonomous_trust.core import register_backend_prefix

register_backend_prefix('autonomous_trust.first_contact.')

# The names the core's contacts package offered, for its callers (tools, apps,
# tests): ``from autonomous_trust.first_contact import Contacts``.
from autonomous_trust.first_contact._python import *  # noqa: E402,F401,F403
from autonomous_trust.first_contact._python import __all__  # noqa: E402,F401
