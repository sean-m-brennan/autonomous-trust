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

# Native C-backed wrappers (renamed to avoid intercepting _python imports)
from ._netconfig import NetworkConfig
from .message import NetWireMessage, RecipientType
# No native ping: C does not implement one. The C network process answers the
# `ping` selector with {"error": "unsupported"} and Python is the only
# implementation, so `ping`/`PingATStats` below are the Python ones on both
# backends. (There was a `native_ping` wrapping the C `ping()` here; nothing
# imported it, and the C function it bound is gone.)

# Delegate to Python for API-compatible classes
from ..._python.network.network import Network
from ..._python.network.message import Message
from ..._python.network.netprocess import NetworkProcess, NetworkProtocol
from ..._python.network.tcp import TCPNetworkProcess
from ..._python.network.udp import UDPNetworkProcess
from ..._python.network.ping_at import PingATServer, PingATStats, ping_at
