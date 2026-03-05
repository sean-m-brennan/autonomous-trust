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

"""
Native capability wrappers.

The C capability registry uses ``__attribute__((constructor))`` for
static registration. Python-side capabilities (Capability, Capabilities,
PeerCapabilities) are reused from the pure-Python backend since they
are serialization/config objects, not performance-critical.

This module provides a bridge to query the C capability registry.
"""

from ._ffi import ffi, lib

# Re-export Python capability classes for API compatibility
from .._python.capabilities import Capability, Capabilities, PeerCapabilities


def find_capability(name: str):
    """Look up a capability by name in the C registry.

    Returns the raw CFFI ``capability_t *`` pointer, or None if not found.
    """
    name_buf = ffi.new('char[]', name.encode('utf-8'))
    ptr = lib.find_capability(name_buf)
    if ptr == ffi.NULL:
        return None
    return ptr
