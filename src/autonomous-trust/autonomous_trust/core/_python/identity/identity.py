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

import secrets
import time
import uuid as uuid_mod

from nacl.public import Box
from nacl.encoding import HexEncoder

from ..config import Configuration, InitializableConfig
from ..system import encoding, agreement_impl
from ..algorithms.agreement import AgreementVoter
from .sign import Signature
from .encrypt import Encryptor
from autonomous_trust.core.protobuf.identity import identity_pb2

class Identity(InitializableConfig, AgreementVoter):
    """
    Identity details that can be saved to file or transmitted
    """
    _msg_class = identity_pb2.Identity
    enc = encoding

    def __init__(self, _uuid, address, _fullname, _nickname, _signature, _encryptor, petname='',
                 _public_only=True, _rank=0, _block_impl=agreement_impl):
        Configuration.__init__(self, identity_pb2.Identity)
        AgreementVoter.__init__(self, str(_uuid), _rank)
        self.address = address  # corresponds to one address in Network config
        self._fullname = _fullname
        self._nickname = _nickname
        self._signature = _signature  # signatures are for one-to-many verification
        self._encryptor = _encryptor  # one-to-one encryption
        self.petname = petname
        self._public_only = _public_only
        self._block_impl = _block_impl

    def __eq__(self, other):
        return self.__class__.__name__ == other.__class__.__name__ and self.uuid == other.uuid and \
            self.address == other.address and \
            self.fullname == other.fullname and self.nickname == other.nickname and \
            self.signature == other.signature and self.encryptor == other.encryptor

    @property
    def uuid(self):
        return self._uuid

    @property
    def fullname(self):
        return self._fullname

    @property
    def nickname(self):
        return self._nickname

    @property
    def signature(self):
        return self._signature

    @property
    def encryptor(self):
        return self._encryptor

    @property
    def block_impl(self):
        return self._block_impl

    def sign(self, msg):
        """
        Sign my own message
        :param msg: bytes
        :return: SignedMessage (msg, sig)
        """
        if isinstance(msg, str):
            msg = msg.encode(self.enc)
        elif isinstance(msg, Configuration):
            msg = msg.to_string().encode(self.enc)
        if self._public_only or self.signature.private is None:
            raise RuntimeError('Cannot sign a message with another identity (%s is not you)' % self.nickname)
        return self.signature.private.sign(msg, encoder=HexEncoder)

    def verify(self, msg, signature=None):
        """
        Verify someone else's signature
        :param msg: SignedMessage (msg, sig) or bytes
        :param signature: sig, if msg was bytes
        :return: bytes
        """
        if isinstance(msg, str):
            msg = msg.encode(self.enc)
        elif isinstance(msg, Configuration):
            msg = msg.to_string().encode(self.enc)
        if signature is None:  # msg is a tuple
            return self.signature.public.verify(msg, encoder=HexEncoder)
        return self.signature.public.verify(msg, signature, encoder=HexEncoder)

    def encrypt(self, msg, whom, nonce=None):
        """
        Encrypt my own message
        :param msg: bytes
        :param whom: destination Identity
        :param nonce: bytes
        :return: EncryptedMessage (nonce, ciphertext)
        """
        if self._public_only or self.encryptor.private is None:
            raise RuntimeError('Cannot encrypt a message with another identity (%s is not you)' % self.nickname)
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
        plaintext = Box(self.encryptor.private, whom.encryptor.public).decrypt(msg, nonce)
        try:
            return plaintext.decode('utf-8')
        except (UnicodeDecodeError, AttributeError):
            return plaintext

    def publish(self):
        return Identity(self.uuid, self.address, self.fullname, self.nickname,
                        Signature(self.signature.publish(), True), Encryptor(self.encryptor.publish(), True),
                        self.petname, True, _rank=self._rank,
                        _block_impl=self._block_impl)

    def sync_to_message(self):
        self.message.uuid = str(self.uuid).encode('utf-8')
        self.message.address = self.address
        self.message.fullname = self._fullname
        self.message.rank = self._rank
        self._signature.message = self.message.signature
        self._signature.sync_to_message()
        self._encryptor.message = self.message.encryptor
        self._encryptor.sync_to_message()

    def sync_from_message(self):
        self._uuid = self.message.uuid.decode('utf-8')
        self.address = self.message.address
        self._fullname = self.message.fullname
        self._nickname = ''
        self.petname = ''
        self._public_only = True
        self._rank = self.message.rank
        self._block_impl = agreement_impl
        self._signature = Signature.__new__(Signature)
        self._signature.message = identity_pb2.Signature()
        self._signature.message.CopyFrom(self.message.signature)
        self._signature.sync_from_message()
        self._encryptor = Encryptor.__new__(Encryptor)
        self._encryptor.message = identity_pb2.Encryptor()
        self._encryptor.message.CopyFrom(self.message.encryptor)
        self._encryptor.sync_from_message()

    @staticmethod
    def initialize(my_name, my_nickname, my_address):
        if '/' in my_address:
            my_address = my_address.split('/')[0]
        time.sleep(secrets.randbelow(1000) / 1000.0)  # reduce chance of collision
        return Identity(uuid_mod.uuid4(), my_address, my_name, my_nickname,
                        Signature.generate(), Encryptor.generate(), 'me', False)
