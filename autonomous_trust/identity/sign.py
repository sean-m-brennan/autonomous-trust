from nacl.signing import SigningKey, VerifyKey
from nacl.encoding import HexEncoder

from ..config.configuration import Configuration


class Signature(Configuration):
    def __init__(self, hex_seed, public_only=True):
        self.public_only = public_only
        if public_only:
            self.private = None
            self.public = VerifyKey(hex_seed, encoder=HexEncoder)
        else:
            self.private = SigningKey(hex_seed, encoder=HexEncoder)
            self.public = self.private.verify_key

    def __eq__(self, other):
        return self.publish() == other.publish()

    @staticmethod
    def generate():
        return Signature(SigningKey.generate().encode(encoder=HexEncoder), False)

    def publish(self):
        return self.public.encode(encoder=HexEncoder)

    def __repr__(self):
        return '%s(hex_seed=%s)' % (self.__class__.__name__, self.publish())

    def to_dict(self):
        if self.public_only:
            seed = self.publish()
        else:
            seed = self.private.encode(encoder=HexEncoder)
        return dict(hex_seed=seed, public_only=self.public_only)

    def serialize(self):  # WARNING: serialization of signature keys is insecure if physically breached
        return self.private.encode(encoder=HexEncoder)
