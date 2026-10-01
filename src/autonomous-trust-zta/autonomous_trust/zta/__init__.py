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
"""Zero Trust credential integration (FEATURE_SPLIT_PLAN Phase 6), as a
distribution separate from the core: the X.509, OIDC and MFA verifiers, the
zta_policy, the admission gate, the credential->identity binding and
background re-verification.

Laid out as the core is, ``_python`` beside ``_native`` (FEATURE_SPLIT_PLAN D2),
so ``autonomous_trust.zta.zta_policy`` resolves through the core's backend
redirector. The native side is empty: the C twin is its own library
(``libat_zta``, src/c/extensions/zta/), and this package is pure Python on
either backend.

Importing it changes nothing. The core finds it through ``_at_extension.py``
(a source tree) or the ``autonomous_trust.extensions`` entry point (an
install), and a node enforces ZTA only when its zta_policy.cfg.json enables it.
"""
from autonomous_trust.core import register_backend_prefix

register_backend_prefix('autonomous_trust.zta.')

# The names the core's identity.zta package offered, for its callers (the
# operator distribution, tests): ``from autonomous_trust.zta import ZtaPolicy``.
from autonomous_trust.zta._python import *  # noqa: E402,F401,F403
from autonomous_trust.zta._python import __all__  # noqa: E402,F401
