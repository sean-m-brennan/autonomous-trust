import uuid as uuid_mod
from nacl.signing import SigningKey, VerifyKey
from nacl.public import PrivateKey, PublicKey, Box
from nacl.encoding import HexEncoder
from .configuration import Configuration


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
    def __init__(self, uuid, address, nickname, petname, signature, encryptor, public_only=True):
        self.uuid = str(uuid)
        self.address = address
        self.nickname = nickname
        self.petname = petname
        self.signature = signature  # signatures are for one-to-many verification
        self.encryptor = encryptor  # one-to-one encryption
        self.public_only = public_only

    def sign(self, msg):
        if self.public_only or self.signature.private is None:
            raise RuntimeError('Cannot sign a message with another identity (%s is not you)' % self.nickname)
        return self.signature.private.sign(msg, encoder=HexEncoder)

    def verify(self, msg, signature=None):
        if signature is None:
            return self.signature.public.verify(msg, encoder=HexEncoder)
        return self.signature.public.verify(msg, signature, encoder=HexEncoder)

    def encrypt(self, msg, whom, nonce=None):
        if self.public_only or self.encryptor.private is None:
            raise RuntimeError('Cannot encrypt a message with another identity (%s is not you)' % self.nickname)
        if isinstance(msg, str):
            msg = msg.encode()
        return Box(self.encryptor.private, whom.encryptor.public).encrypt(msg, nonce)

    def decrypt(self, msg, whom, nonce=None):
        return Box(self.encryptor.private, whom.encryptor.public).decrypt(msg, nonce)  # FIXME decode?

    def publish(self):
        return Identity(self.uuid, self.address, self.nickname, self.petname,
                        Signature(self.signature.publish(), True), Encryptor(self.encryptor.publish(), True), True)

    @staticmethod
    def initialize(my_name, my_address):
        return Identity(uuid_mod.uuid4(), my_address, my_name, 'me', Signature.generate(), Encryptor.generate(), False)


class Peers(Configuration):
    LEVELS = 3

    def __init__(self, hierarchy=None):
        self.hierarchy = hierarchy
        if hierarchy is None:
            self.hierarchy = [dict({}) for _ in range(self.LEVELS)]

    @staticmethod
    def _index_by(who):
        return who.nickname

    def _find(self, index):
        for idx in range(len(self.hierarchy)):
            if index in self.hierarchy[idx].keys():
                return idx
        return

    def find(self, index):
        idx = self._find(index)
        if idx is not None:
            return self.hierarchy[idx][index]

    def promote(self, who):
        index = self._index_by(who)
        idx = self._find(index)
        if idx is not None:
            if idx > 0:
                self.hierarchy[idx-1][index] = who
                del self.hierarchy[idx][index]
        else:
            self.hierarchy[-1][index] = who

    def demote(self, who):
        index = self._index_by(who)
        idx = self._find(index)
        if idx is not None:
            if idx < len(self.hierarchy):
                self.hierarchy[idx+1][index] = who
            del self.hierarchy[idx][index]


# TODO identity blockchain
