import uuid as uuid_mod

from nacl.public import Box
from nacl.encoding import HexEncoder

from ..config.configuration import Configuration
from .blocks import ChainImpl
from .sign import Signature
from .encrypt import Encryptor


class Identity(Configuration):
    """
    Identity details that can be saved to file or transmitted
    """
    def __init__(self, _uuid, address, _fullname, _nickname, _signature, _encryptor, petname='',
                 _public_only=True, _block_impl=ChainImpl.POA.value):
        self._uuid = str(_uuid)
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
        return Box(self.encryptor.private, whom.encryptor.public).decrypt(msg, nonce)  # TODO decode?

    def publish(self):
        return Identity(self.uuid, self.address, self.fullname, self.nickname,
                        Signature(self.signature.publish(), True), Encryptor(self.encryptor.publish(), True),
                        self.petname, True)

    @staticmethod
    def initialize(my_name, my_nickname, my_address):
        return Identity(uuid_mod.uuid4(), my_address, my_name, my_nickname,
                        Signature.generate(), Encryptor.generate(), 'me', False)
