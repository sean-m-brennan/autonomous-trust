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

"""Fixtures for native/Python comparison tests."""

import os
import pytest


def _have_native():
    """Check if the native C library is available."""
    try:
        from autonomous_trust.core._native._ffi import lib  # noqa
        return True
    except Exception:
        return False


requires_native = pytest.mark.skipif(
    not _have_native(),
    reason="Native C library (libautonomous_trust.so) not available"
)
