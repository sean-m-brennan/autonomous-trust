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

import logging
from typing import Any, Optional

import icontract

from .system import CfgIds, QueueType
from .util import ClassEnumMeta
from .identity import Group, ChildGroupSet, Peers, ZtaStanding
from .network import Message
from .capabilities import Capabilities, PeerCapabilities


class Protocol(object, metaclass=ClassEnumMeta):
    def __init__(self, proc_name: str, logger: logging.Logger, configurations: Optional[dict[str, Any]]):
        self.proc_name = proc_name
        self.logger = logger
        self.peers = Peers()
        self.peer_capabilities = PeerCapabilities()
        self.group = None
        # Child groups this node gateways (group-uuid-str -> Group),
        # propagated from IdentityProcess via a ChildGroupSet message.
        # Empty on leaf nodes; kept separate from self.group so the
        # primary/parent group slot is never clobbered.
        self.child_groups = {}
        # peer-uuid-str -> ZtaStanding, propagated from IdentityProcess
        # (ISSUES §10.5). This node's OWN findings about its peers, never
        # anything a peer asserted about itself; reputation reads it to bound
        # a peer whose credential ZTA has not actually proved.
        self.zta_standing = {}
        if configurations is not None:
            if CfgIds.peers in configurations:
                self.peers = configurations[CfgIds.peers]
            if CfgIds.capabilities in configurations:
                self.peer_capabilities = configurations[CfgIds.capabilities]
            if CfgIds.group in configurations:
                self.group = configurations[CfgIds.group]
        self.capabilities = Capabilities()
        self.handlers = {}

    def register_handler(self, func_name: str, handler):
        self.handlers[func_name] = handler

    @icontract.require(lambda queues: len(queues) > 0)
    @icontract.require(lambda message: message is not None)
    def run_message_handlers(self, queues: dict[str, QueueType], message: Message):
        if isinstance(message, Group):
            self.group = message
            return True
        if isinstance(message, ChildGroupSet):
            self.child_groups = message.groups
            return True
        if isinstance(message, ZtaStanding):
            # Last writer wins, deliberately: IdentityProcess is the single
            # source of ZTA findings and sends these in the order it learns
            # them, so the newest verdict is the current one (§10.5).
            self.zta_standing[message.peer_uuid] = message
            return True
        if isinstance(message, Peers):
            self.peers = message
            return True
        if isinstance(message, Capabilities):
            self.capabilities = message
            return True
        if isinstance(message, PeerCapabilities):
            self.peer_capabilities = message
            return True
        if isinstance(message, Message):
            if message.process == self.proc_name:
                for name, handler in self.handlers.items():
                    if name == message.function:
                        return self.handlers[name](queues, message)
        return False
