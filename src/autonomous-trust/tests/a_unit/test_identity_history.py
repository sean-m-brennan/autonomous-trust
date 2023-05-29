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
        hist.upgrade_peer(ident)
        peers.promote(ident)
