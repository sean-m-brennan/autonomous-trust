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

# Native C-backed wrappers (renamed to avoid intercepting _python imports)
from ._netconfig import NetworkConfig
from .message import NetWireMessage, RecipientType
from ._ping_native import PingStats as NativePingStats, ping as native_ping

# Delegate to Python for API-compatible classes
from ..._python.network.network import Network
from ..._python.network.message import Message
from ..._python.network.netprocess import NetworkProcess, NetworkProtocol
from ..._python.network.tcp import TCPNetworkProcess
from ..._python.network.udp import UDPNetworkProcess
from ..._python.network.ping import PingServer, PingStats, ping
