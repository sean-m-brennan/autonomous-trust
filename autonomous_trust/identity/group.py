import uuid as uuid_mod

from nacl.public import Box

from ..config import Configuration
from .encrypt import Encryptor


class Group(Configuration):
    """
    Group identity details that can be saved to file or transmitted
    """
    def __init__(self, _uuid, addresses, _nickname, _encryptor, _public_only=True):
        self._uuid = str(_uuid)
        self.addresses = addresses
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
    def initialize(addresses, our_nickname):
        return Group(uuid_mod.uuid4(), addresses, our_nickname, Encryptor.generate(), False)
