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

from uuid import uuid4
import secrets

from autonomous_trust.core.identity import Identity, Peers, Signature
from autonomous_trust.core.identity.history import IdentityByAuthority


def _random_identity():
    seed = secrets.token_hex(32)
    return Identity(uuid4(), '127.0.0.1', 'full name', 'nick', Signature(seed), None)


def test_add_peer():
    peers = Peers()
    ident = _random_identity()
    hist = IdentityByAuthority(ident, peers, None, 5)
    for _ in range(10):
        ident = _random_identity()
        peers.promote(ident)
