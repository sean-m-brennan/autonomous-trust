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

# Native C-backed wrappers (available under prefixed names)
from ._native_wrappers import (
    JobQueue as NativeJobQueue,
    TaskTracker as NativeTaskTracker,
)

# API-compatible exports from Python backend
from ..._python.negotiation.protocol import NegotiationProtocol
from ..._python.negotiation.negotiation import (
    Task, TaskParameters, TaskStatus, Status, TaskResult,
    JobQueue, TaskTracker,
)
from ..._python.negotiation.negprocess import NegotiationProcess
# Anything this shim does not name above falls back to the `_python` twin, so
# the import surface does not depend on which backend is active. See
# _delegate.python_fallback -- explicit re-exports above always win.
from .._delegate import python_fallback

__getattr__ = python_fallback(__name__)
