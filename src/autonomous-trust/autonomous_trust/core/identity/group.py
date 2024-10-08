# ******************
#  Copyright 2024 TekFive, Inc. and contributors
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

import random
import time
import uuid as uuid_mod

from nacl.public import Box

from ..config import InitializableConfig
from .encrypt import Encryptor
from ..protobuf.identity import identity_pb2


class Group(InitializableConfig):
    """
    Group identity details that can be saved to file or transmitted
    """
    def __init__(self, _uuid, _address_map, _nickname, _encryptor, _public_only=True):
        super().__init__(identity_pb2.Group)
        self._uuid = str(_uuid)
        self._address_map = _address_map
        self._nickname = _nickname
        self._encryptor = _encryptor  # group-shared key
        self._public_only = _public_only

    def __eq__(self, other):
        if not isinstance(other, self.__class__):
            return False
        return self.uuid == other.uuid and self.encryptor.publish() == other.encryptor.publish()

    @property
    def uuid(self):
        return self._uuid

    @property
    def nickname(self):
        return self._nickname

    @property
    def addresses(self):
        return self._address_map.values()

    def add_address(self, uuid, address):
        inv = {v: k for k, v in self._address_map.items()}
        if address in inv and inv[address] != uuid:
            del self._address_map[inv[address]]  # address collision
        self._address_map[uuid] = address

    @property
    def encryptor(self):
        return self._encryptor

    def encrypt(self, msg, whom, nonce=None):
        """
        Encrypt my own message
        :param msg: bytes
        :param whom: destination Identity
        :param nonce: bytes
        :return: EncryptedMessage (nonce, ciphertext)
        """
        if self._public_only or self.encryptor.private is None:
            raise RuntimeError('Cannot encrypt a message for another group (you are not part of %s)' % self.nickname)
        if isinstance(msg, str):
            msg = msg.encode()
        return Box(self.encryptor.private, whom.encryptor.public).encrypt(msg, nonce)

    def decrypt(self, msg, whom, nonce=None):
        """
        Decrypt someone else's message
        :param msg: EncryptedMessage (nonce, ciphertext)
        :param whom: sender Identity
        :param nonce: bytes
        :return: bytes
        """
        return Box(self.encryptor.private, whom.encryptor.public).decrypt(msg, nonce)  # TODO decode?

    def publish(self):
        return Group(self.uuid, self.addresses, self.nickname, Encryptor(self.encryptor.publish(), True), True)

    @staticmethod
    def initialize(address_map, our_nickname):
        time.sleep(random.random())  # reduce chance of collision
        return Group(uuid_mod.uuid4(), address_map, our_nickname, Encryptor.generate(), False)
