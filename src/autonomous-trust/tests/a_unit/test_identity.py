import os
import uuid as uuid_mod
from autonomous_trust.core.config import Configuration
from autonomous_trust.core.identity import Identity, Peers, Signature, Encryptor

from .. import TEST_DIR


def test_my_id(setup_teardown):
    t1 = Identity.initialize('me.myself.i', 'myself', '127.0.0.1')
    file = os.path.join(TEST_DIR, 'test_my_id')
    t1.to_file(file)
    t2 = Configuration.from_file(file)
    assert repr(t1) == repr(t2)


def test_sig(setup_teardown):
    t1 = Identity.initialize('me.myself.i', 'myself', '127.0.0.1')
    file = os.path.join(TEST_DIR, 'test_sig')
    t1.to_file(file)
    t2 = t1.publish()
    msg = t1.sign(b'Message')
    t2.verify(msg)


def test_peers(setup_teardown):
    t3 = Peers()
    p1 = Identity(uuid_mod.uuid4(), '123.4.5.67', 'peer1', 'p1', Signature.generate(), Encryptor.generate())
    p2 = Identity(uuid_mod.uuid4(), '123.5.6.78', 'peer2', 'p2', Signature.generate(), Encryptor.generate())
    p3 = Identity(uuid_mod.uuid4(), '123.6.7.89', 'peer3', 'p3', Signature.generate(), Encryptor.generate())
    assert p1 != p2
    assert p2 != p3
    t3.promote(p1)
    t3.promote(p2)
    t3.promote(p1)
    t3.promote(p3)
    t3.promote(p2)
    t3.promote(p1)
    file = os.path.join(TEST_DIR, 'test_peers')
    t3.to_file(file)
    t4 = Configuration.from_file(file)
    print(t3.listing)
    print(t4.listing)
    assert repr(t3) == repr(t4)
