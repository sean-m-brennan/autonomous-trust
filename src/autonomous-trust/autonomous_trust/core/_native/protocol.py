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
Native protocol dispatch — reuses Python Protocol base class.

The C protocol dispatch is internal to process_run() and not directly
exposed. For the native backend, downstream Process subclasses continue
using the Python Protocol base class with register_handler().
"""

# Re-export from Python backend — protocol dispatch is Python-level
from .._python.protocol import Protocol
