import uuid as uuid_mod

from nacl.signing import SigningKey, VerifyKey
from nacl.public import PrivateKey, PublicKey, Box
from nacl.encoding import HexEncoder

from ..config.configuration import Configuration
from .blocks import ChainImpl


class Signature(Configuration):
    def __init__(self, hex_seed, public_only=True):
        if public_only:
            self.private = None
            self.public = VerifyKey(hex_seed, encoder=HexEncoder)
        else:
            self.private = SigningKey(hex_seed, encoder=HexEncoder)
            self.public = self.private.verify_key

    @staticmethod
    def generate():
        return Signature(SigningKey.generate().encode(encoder=HexEncoder), False)

    def publish(self):
        return self.public.encode(encoder=HexEncoder)

    def __repr__(self):
        return '%s(hex_seed=%s)' % (self.__class__.__name__, self.publish())

    def to_dict(self):
        return dict(hex_seed=self.publish())

    def serialize(self):  # WARNING: serialization of signature keys is insecure if physically breached
        return self.private.encode(encoder=HexEncoder)


class Encryptor(Configuration):
    def __init__(self, hex_seed, public_only=True):
        if public_only:
            self.private = None
            self.public = PublicKey(hex_seed, encoder=HexEncoder)
        else:
            self.private = PrivateKey(hex_seed, encoder=HexEncoder)
            self.public = self.private.public_key

    @staticmethod
    def generate():
        return Encryptor(PrivateKey.generate().encode(encoder=HexEncoder), False)

    def publish(self):
        return self.public.encode(encoder=HexEncoder)

    def __repr__(self):
        return '%s(hex_seed=%s)' % (self.__class__.__name__, self.publish())

    def to_dict(self):
        return dict(hex_seed=self.publish())

    def serialize(self):  # WARNING: serialization of signature keys is insecure if physically breached
        return self.private.encode(encoder=HexEncoder)


class Identity(Configuration):
    def __init__(self, _uuid, net_cfg, _fullname, _nickname, _signature, _encryptor, petname='',
                 _public_only=True, _block_impl=ChainImpl.POA.value):
        self._uuid = str(_uuid)
        self.net_cfg = net_cfg  # full Network obj
        self._fullname = _fullname
        self._nickname = _nickname
        self._signature = _signature  # signatures are for one-to-many verification
        self._encryptor = _encryptor  # one-to-one encryption
        self.petname = petname
        self._public_only = _public_only
        self._block_impl = _block_impl

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
        if self._public_only or self.signature.private is None:
            raise RuntimeError('Cannot sign a message with another identity (%s is not you)' % self.nickname)
        return self.signature.private.sign(msg, encoder=HexEncoder)

    def verify(self, msg, signature=None):
        if signature is None:
            return self.signature.public.verify(msg, encoder=HexEncoder)
        return self.signature.public.verify(msg, signature, encoder=HexEncoder)

    def encrypt(self, msg, whom, nonce=None):
        if self._public_only or self.encryptor.private is None:
            raise RuntimeError('Cannot encrypt a message with another identity (%s is not you)' % self.nickname)
        if isinstance(msg, str):
            msg = msg.encode()
        return Box(self.encryptor.private, whom.encryptor.public).encrypt(msg, nonce)

    def decrypt(self, msg, whom, nonce=None):
        return Box(self.encryptor.private, whom.encryptor.public).decrypt(msg, nonce)  # TODO decode?

    def publish(self):
        return Identity(self.uuid, self.net_cfg, self.fullname, self.nickname,
                        Signature(self.signature.publish(), True), Encryptor(self.encryptor.publish(), True),
                        self.petname, True)

    @staticmethod
    def initialize(my_name, my_nickname, my_network):
        return Identity(uuid_mod.uuid4(), my_network, my_name, my_nickname,
                        Signature.generate(), Encryptor.generate(), 'me', False)


class Peers(Configuration):
    LEVELS = 3

    def __init__(self, hierarchy=None, listing=None):
        self.hierarchy = hierarchy
        if hierarchy is None:
            self.hierarchy = [dict({}) for _ in range(self.LEVELS)]
        self.listing = {}

    @staticmethod
    def _index_by(who):
        return who.nickname

    def _find(self, index):
        for idx in range(len(self.hierarchy)):
            if index in self.hierarchy[idx].keys():
                return idx
        return

    def find_by_index(self, index):
        idx = self._find(index)
        if idx is not None:
            return self.hierarchy[idx][index]

    def find_by_address(self, address):
        if address in self.listing.keys():
            return self.listing[address]
        return

    def promote(self, who):
        if who.address not in self.listing.keys():
            self.listing[who.address] = who
        index = self._index_by(who)
        idx = self._find(index)
        if idx is not None:
            if idx > 0:
                self.hierarchy[idx - 1][index] = who
                del self.hierarchy[idx][index]
        else:
            self.hierarchy[-1][index] = who

    def demote(self, who):
        index = self._index_by(who)
        idx = self._find(index)
        if idx is not None:
            if idx < len(self.hierarchy):
                self.hierarchy[idx + 1][index] = who
            else:
                del self.listing[who.address]
            del self.hierarchy[idx][index]
