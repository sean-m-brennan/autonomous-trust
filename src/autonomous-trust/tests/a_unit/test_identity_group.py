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
import pytest
from uuid import uuid4
from unittest.mock import MagicMock, patch

from autonomous_trust.core.identity.group import Group
from autonomous_trust.core.identity.encrypt import Encryptor


class TestGroup:
    def test_init(self):
        enc = Encryptor.generate()
        uid = uuid4()
        addr_map = {'peer1': '10.0.0.1'}
        g = Group(uid, addr_map, 'testgroup', enc, _public_only=False)
        assert g.uuid == str(uid)
        assert g.nickname == 'testgroup'
        assert g.encryptor is enc

    def test_addresses(self):
        enc = Encryptor.generate()
        addr_map = {'peer1': '10.0.0.1', 'peer2': '10.0.0.2'}
        g = Group(uuid4(), addr_map, 'testgroup', enc)
        assert '10.0.0.1' in g.addresses
        assert '10.0.0.2' in g.addresses

    def test_add_address(self):
        enc = Encryptor.generate()
        addr_map = {}
        g = Group(uuid4(), addr_map, 'testgroup', enc)
        g.add_address('peer1', '10.0.0.1')
        assert '10.0.0.1' in g.addresses

    def test_add_address_collision(self):
        enc = Encryptor.generate()
        addr_map = {'peer1': '10.0.0.1'}
        g = Group(uuid4(), addr_map, 'testgroup', enc)
        g.add_address('peer2', '10.0.0.1')  # same address, different uuid
        assert '10.0.0.1' in g.addresses
        assert 'peer1' not in g._address_map  # old peer removed

    def test_eq(self):
        enc = Encryptor.generate()
        uid = uuid4()
        g1 = Group(uid, {}, 'g1', enc)
        g2 = Group(uid, {}, 'g2', enc)
        assert g1 == g2

    def test_eq_different_uuid(self):
        enc = Encryptor.generate()
        g1 = Group(uuid4(), {}, 'g', enc)
        g2 = Group(uuid4(), {}, 'g', enc)
        assert g1 != g2

    def test_eq_not_group(self):
        enc = Encryptor.generate()
        g = Group(uuid4(), {}, 'g', enc)
        assert g != 'not_a_group'

    def test_encrypt_public_only_raises(self):
        enc = Encryptor.generate()
        g = Group(uuid4(), {}, 'g', enc, _public_only=True)
        whom = MagicMock()
        whom.encryptor = MagicMock()
        whom.encryptor.public = Encryptor.generate().public
        with pytest.raises(RuntimeError, match='Cannot encrypt'):
            g.encrypt(b'hello', whom)

    def test_encrypt_decrypt(self):
        enc1 = Encryptor.generate()
        enc2 = Encryptor.generate()
        g1 = Group(uuid4(), {}, 'g1', enc1, _public_only=False)

        whom = MagicMock()
        whom.encryptor = MagicMock()
        whom.encryptor.public = enc2.public

        encrypted = g1.encrypt(b'hello world', whom)

        # Decrypt with g2 having enc2 private key and g1's public key
        g2 = Group(uuid4(), {}, 'g2', enc2, _public_only=False)
        sender = MagicMock()
        sender.encryptor = MagicMock()
        sender.encryptor.public = enc1.public
        decrypted = g2.decrypt(encrypted, sender)
        assert decrypted == b'hello world'

    def test_encrypt_string(self):
        enc1 = Encryptor.generate()
        enc2 = Encryptor.generate()
        g1 = Group(uuid4(), {}, 'g1', enc1, _public_only=False)
        whom = MagicMock()
        whom.encryptor = MagicMock()
        whom.encryptor.public = enc2.public
        encrypted = g1.encrypt('hello string', whom)
        assert encrypted is not None

    def test_publish(self):
        enc = Encryptor.generate()
        g = Group(uuid4(), {'p1': '10.0.0.1'}, 'pub_test', enc, _public_only=False)
        pub = g.publish()
        assert pub._public_only is True
        assert pub.nickname == 'pub_test'

    def test_initialize(self):
        with patch('autonomous_trust.core.identity.group.time.sleep'):
            g = Group.initialize({'p1': '10.0.0.1'}, 'init_test')
        assert g.nickname == 'init_test'
        assert g._public_only is False
