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
"""The verification layers of R+D.md §12 (FEATURE_SPLIT_PLAN Phase 3):
physical consistency, calibration, certificates, prequential competence and
replicated execution, as a distribution separate from the core.

Laid out as the core is, ``_python`` beside ``_native`` (FEATURE_SPLIT_PLAN D2),
so ``autonomous_trust.oracle.physics`` resolves through the core's backend
redirector. The native side is empty: each layer's C twin is its own library
(``libat_<layer>``, src/c/extensions/<layer>/), and the Python layers are
pure Python on either backend.

Importing this package registers nothing. The core finds the layers through
``_at_extension.py`` (a source tree) or the ``autonomous_trust.extensions``
entry point (an install); that module imports the five, and each registers
its arms with ``autonomous_trust.core.oracles``.
"""
from autonomous_trust.core import register_backend_prefix

register_backend_prefix('autonomous_trust.oracle.')
