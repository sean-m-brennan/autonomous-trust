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

from nacl.signing import SigningKey, VerifyKey
from nacl.encoding import HexEncoder

from ..config.configuration import Configuration
from ..protobuf import identity_pb2

class Signature(Configuration):
    def __init__(self, hex_seed, public_only=True):
        super().__init__(identity_pb2.Signature)
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
