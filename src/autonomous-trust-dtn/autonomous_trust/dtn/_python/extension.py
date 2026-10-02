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
"""The DTN extension as the core sees it. It registers no handlers: what it
brings is a transport, which a node names as its own
(``AT_TRANSPORT``) or as a leg of the hybrid transport, by C's name ``dtn_bp``.
"""
from autonomous_trust.core.extensions import Extension

#: The transport's class path, and its name in both runtimes.
TRANSPORT_KIND = 'dtn_bp'
TRANSPORT_CLASS = 'autonomous_trust.dtn.transport.DTNNetworkProcess'


def _register_handlers(proc, proc_name):  # noqa: ARG001
    pass


EXTENSION = Extension(
    name='dtn',
    enabled=lambda: True,
    register_handlers=_register_handlers,
    transports=((TRANSPORT_KIND, TRANSPORT_CLASS),),
)
