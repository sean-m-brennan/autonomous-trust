# ******************
#  Copyright 2026 TekFive, Inc., Sean M. Brennan, and contributors
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
"""The opt-in operator key: WHICH human guards a node, and the proof.

These drive the REAL verifiers — minted CAs, real X.509 chain walks, real PIV
signatures over the real pre-image — because the thing under test is whether a
signature made by one holder verifies for one node and nobody else. A stubbed
verifier could not tell.

The cases are organised around the three outcomes the design admits: declined
(the default, and it must cost nothing), verified, and refused. Refusal must never
demote `operator_bound`, which is earned independently.
"""
import base64
import hashlib
import logging
import os
import sys
from types import SimpleNamespace
from uuid import UUID

import pytest

pytest.importorskip("cryptography")

_ROOT = os.path.dirname(os.path.abspath(__file__))
while _ROOT != '/':
    if os.path.isfile(os.path.join(_ROOT, 'tools', 'provision_zta_certs.py')):
        break
    _ROOT = os.path.dirname(_ROOT)
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from tools.provision_zta_certs import (  # noqa: E402
    make_ca, make_leaf_keypair, ca_bundle_pem, cert_der)

from autonomous_trust.core._python.identity.identity import Identity  # noqa: E402
from autonomous_trust.core._python.identity.sign import Signature  # noqa: E402
from autonomous_trust.core._python.identity.encrypt import Encryptor  # noqa: E402
from autonomous_trust.core._python.identity.idprocess import IdentityProcess  # noqa: E402
from autonomous_trust.core._python.identity.operator_binding import (  # noqa: E402
    OPERATOR_BINDING_PREIMAGE_LEN, OPERATOR_BINDING_TAG, OPERATOR_PUBKEY_LEN,
    node_signing_pubkey, operator_binding_preimage, verify_operator_binding)
from autonomous_trust.core.identity.zta import ZtaPolicy, BINDING_MODE_OFF  # noqa: E402
from autonomous_trust.core.identity.zta.piv.pkcs11 import SoftwareToken  # noqa: E402


GUARDIAN_KEY = bytes(range(32))          # a stand-in ed25519 public key
OTHER_KEY = bytes(range(32, 64))


def _identity(tag: str, seed: bytes = b'11') -> Identity:
    """A deterministic identity, so a binding made here is reproducible across
    runs. NOT `hash(tag)`: str hashing is salted per process, which would make the
    uuid — and therefore the signed pre-image — differ run to run."""
    digest = hashlib.md5(tag.encode()).digest()   # a label, not a security claim
    return Identity(UUID(bytes=digest), '10.0.0.1',
                    '%s.test' % tag,
                    Signature(seed * 32, public_only=False),
                    Encryptor(b'22' * 32, public_only=False))


class _Gate:
    """The real admission gate, with real verifiers and nothing else."""
    _zta_policy = IdentityProcess._zta_policy
    _zta_verifier = IdentityProcess._zta_verifier
    _zta_operator_verifier = IdentityProcess._zta_operator_verifier
    _zta_admit = IdentityProcess._zta_admit
    _zta_credential_replayed = IdentityProcess._zta_credential_replayed
    _is_operator_credential = IdentityProcess._is_operator_credential
    _mark_operator_bound = staticmethod(IdentityProcess._mark_operator_bound)
    _verify_operator_key = IdentityProcess._verify_operator_key
    _zta_credentials = IdentityProcess._zta_credentials
    _zta_match_anchors = IdentityProcess._zta_match_anchors
    _zta_anchor_verifiers = IdentityProcess._zta_anchor_verifiers

    def __init__(self, bundle_path: str, operator_bundle_path: str):
        # `binding_mode: off`: these fixtures carry an operator-KEY binding (which
        # human) and no credential->identity binding (who may present the cert), and
        # the operator key is the thing under test here. Whether a valid
        # operator-key binding should itself count as a credential binding -- it is
        # a signature by the credential's own key over bytes naming the node, so
        # arguably yes -- is an open question, not something to assume here.
        self.configs = {ZtaPolicy.CONFIG_KEY: ZtaPolicy(
            enabled=True, require_at_admission=True, verifier_type='x509',
            binding_mode=BINDING_MODE_OFF,
            ca_bundle_path=bundle_path,
            operator_ca_bundle_path=operator_bundle_path)}
        self._zta_policy_cache = None
        self._zta_verifier_cache = None
        self._zta_operator_verifier_cache = None
        self._zta_anchor_cache = None
        self._zta_capped = set()
        self._operator_verified = set()
        self.logger = logging.getLogger('test.operator_binding')
        self.peers = SimpleNamespace(all=[])
        self.identity = None


@pytest.fixture
def world(tmp_path):
    """One CA acting as both the mission and the operator anchor (what
    `operator-bound-verified.yaml` does), plus a second, unrelated CA whose leaf
    is a perfectly good credential with no standing to name a guardian."""
    op_ca_key, op_ca_cert = make_ca('Operator Root')
    op_leaf_key, op_leaf_cert = make_leaf_keypair('operator-alpha', op_ca_key,
                                                  op_ca_cert)
    # A second operator-class holder: chains to the operator anchor, so it is a
    # real operator — just not the one a binding claims signed it.
    beta_key, beta_cert = make_leaf_keypair('operator-beta', op_ca_key, op_ca_cert)
    mission_ca_key, mission_ca_cert = make_ca('Mission Root')
    drone_key, drone_cert = make_leaf_keypair('drone-bravo', mission_ca_key,
                                              mission_ca_cert)

    op_bundle = str(tmp_path / 'operator-ca.pem')
    with open(op_bundle, 'wb') as fp:
        fp.write(ca_bundle_pem(op_ca_cert))
    # The mission anchor trusts BOTH roots, so a drone credential is admitted as a
    # peer and simply is not operator-class — the distinction under test.
    mission_bundle = str(tmp_path / 'mission-ca.pem')
    with open(mission_bundle, 'wb') as fp:
        fp.write(ca_bundle_pem(op_ca_cert, mission_ca_cert))

    return SimpleNamespace(
        operator_token=SoftwareToken(cert_der(op_leaf_cert), op_leaf_key),
        drone_token=SoftwareToken(cert_der(drone_cert), drone_key),
        impostor_token=SoftwareToken(cert_der(beta_cert), beta_key),
        operator_bundle=op_bundle,
        mission_bundle=mission_bundle,
    )


def _peer(identity: Identity, cred: bytes, key: bytes = b'',
          binding: bytes = b'') -> Identity:
    """A newly-announced peer as the gate sees it: credential and guardian claim
    delivered, nothing verified yet."""
    identity.zta_credential = cred
    identity.zta_credential_hash = hashlib.sha256(cred).digest()
    identity.zta_issuer = 'PIV:CN=operator-alpha'
    identity.operator_bound = True          # advertised; never trusted
    identity.operator_pubkey = key
    identity.operator_key_binding = binding
    return identity


def _bind(token: SoftwareToken, identity: Identity, key: bytes = GUARDIAN_KEY) -> bytes:
    """What an operator's PIV does at activation."""
    return token.sign(operator_binding_preimage(identity, key))


# --- the pre-image itself ------------------------------------------------------

def test_the_preimage_is_the_tag_the_node_and_the_key():
    ident = _identity('node-a')
    pre = operator_binding_preimage(ident, GUARDIAN_KEY)

    assert len(pre) == OPERATOR_BINDING_PREIMAGE_LEN == 102
    assert pre.startswith(OPERATOR_BINDING_TAG)
    body = pre[len(OPERATOR_BINDING_TAG):]
    assert body[:16] == UUID(str(ident.uuid)).bytes
    assert body[16:48] == node_signing_pubkey(ident)
    assert body[48:] == GUARDIAN_KEY
    # The node is named INSIDE the signed bytes: this is what stops a binding from
    # being lifted onto another node.
    other = _identity('node-b', seed=b'33')
    assert operator_binding_preimage(other, GUARDIAN_KEY) != pre


def test_a_key_of_the_wrong_length_is_a_caller_error_not_a_binding():
    ident = _identity('node-a')
    for bad in (b'', GUARDIAN_KEY[:31], GUARDIAN_KEY + b'\x00'):
        with pytest.raises(ValueError):
            operator_binding_preimage(ident, bad)


# --- declined: the default, and it must cost nothing ---------------------------

def test_declining_is_silent_and_keeps_operator_bound(world):
    """The anonymity guarantee: a node that names no guardian is admitted exactly
    as before, and its operator_bound is untouched."""
    gate = _Gate(world.mission_bundle, world.operator_bundle)
    peer = _peer(_identity('shy'), world.operator_token.certificate_der())

    assert gate._zta_admit(peer) == 'admit'
    assert peer.operator_bound is True          # earned from the anchor
    assert peer.operator_pubkey == b''          # nobody named
    assert peer.uuid in gate._operator_verified


# --- verified ------------------------------------------------------------------

def test_a_valid_binding_is_credited(world):
    gate = _Gate(world.mission_bundle, world.operator_bundle)
    ident = _identity('guarded')
    binding = _bind(world.operator_token, ident)
    peer = _peer(ident, world.operator_token.certificate_der(), GUARDIAN_KEY,
                 binding)

    assert gate._zta_admit(peer) == 'admit'
    assert peer.operator_bound is True
    assert peer.operator_pubkey == GUARDIAN_KEY

    # And the same check standing alone, which is what a consumer would run.
    assert verify_operator_binding(peer, world.operator_token.certificate_der())


# --- refused: each way it can be a lie ----------------------------------------

def test_a_forged_binding_is_refused_and_operator_bound_stands(world):
    """Signed by a different operator-class holder. The credential verifies, the
    node is genuinely operator-attended, and the guardian claim is still refused —
    the two conclusions are independent by design."""
    gate = _Gate(world.mission_bundle, world.operator_bundle)
    ident = _identity('liar')
    forged = _bind(world.impostor_token, ident)
    peer = _peer(ident, world.operator_token.certificate_der(), GUARDIAN_KEY,
                 forged)

    assert gate._zta_admit(peer) == 'admit'
    assert peer.operator_bound is True      # NOT demoted
    assert peer.operator_pubkey == b''      # but no guardian recorded


def test_a_binding_made_for_another_node_is_refused(world):
    """ISSUES.md §1.5's shape: a credential AND its binding harvested from another
    peer's clear-text announce, re-presented under this identity. The signature is
    genuine; it just does not name this node."""
    gate = _Gate(world.mission_bundle, world.operator_bundle)
    victim = _identity('victim')
    harvested = _bind(world.operator_token, victim)

    thief = _peer(_identity('thief', seed=b'44'),
                  world.operator_token.certificate_der(), GUARDIAN_KEY, harvested)
    assert gate._zta_admit(thief) == 'admit'
    assert thief.operator_pubkey == b''

    # Control: the same binding on the node it was made for is credited, so the
    # refusal above is about the node, not about the fixture.
    gate2 = _Gate(world.mission_bundle, world.operator_bundle)
    owner = _peer(victim, world.operator_token.certificate_der(), GUARDIAN_KEY,
                  harvested)
    assert gate2._zta_admit(owner) == 'admit'
    assert owner.operator_pubkey == GUARDIAN_KEY


def test_a_binding_for_a_different_key_is_refused(world):
    """The binding covers the key, so swapping the advertised key invalidates it —
    otherwise one signature would vouch for any guardian."""
    gate = _Gate(world.mission_bundle, world.operator_bundle)
    ident = _identity('swapper')
    binding = _bind(world.operator_token, ident, GUARDIAN_KEY)
    peer = _peer(ident, world.operator_token.certificate_der(), OTHER_KEY, binding)

    assert gate._zta_admit(peer) == 'admit'
    assert peer.operator_pubkey == b''


def test_half_a_claim_is_refused(world):
    """A key with no binding is unverifiable; a binding with no key names nobody."""
    gate = _Gate(world.mission_bundle, world.operator_bundle)
    ident = _identity('halfway')
    binding = _bind(world.operator_token, ident)

    key_only = _peer(_identity('key-only'),
                     world.operator_token.certificate_der(), GUARDIAN_KEY, b'')
    assert gate._zta_admit(key_only) == 'admit'
    assert key_only.operator_pubkey == b''

    gate2 = _Gate(world.mission_bundle, world.operator_bundle)
    binding_only = _peer(ident, world.operator_token.certificate_der(), b'',
                         binding)
    assert gate2._zta_admit(binding_only) == 'admit'
    assert binding_only.operator_pubkey == b''


def test_a_non_operator_credential_cannot_name_a_guardian(world):
    """A drone credential is admitted as a peer and is not operator-class, so its
    binding is never even considered: a human with no standing to name a guardian
    names none. This is the gate the whole design hangs from — without it, any
    peer with any cert could mint a guardian edge."""
    gate = _Gate(world.mission_bundle, world.operator_bundle)
    ident = _identity('drone')
    binding = _bind(world.drone_token, ident)   # genuinely signed, wrong anchor
    peer = _peer(ident, world.drone_token.certificate_der(), GUARDIAN_KEY, binding)

    assert gate._zta_admit(peer) == 'admit'
    assert peer.operator_bound is False         # not operator-class
    assert peer.operator_pubkey == b''
    # ...and the binding itself would verify in isolation, which is exactly why the
    # operator-class check has to come first.
    assert verify_operator_binding(peer, world.drone_token.certificate_der(),
                                   GUARDIAN_KEY, binding)


def test_a_verifier_refuses_a_wrong_length_key_without_raising(world):
    ident = _identity('sloppy')
    binding = _bind(world.operator_token, ident)
    cred = world.operator_token.certificate_der()
    for bad in (b'', GUARDIAN_KEY[:31], GUARDIAN_KEY + b'\x00'):
        assert not verify_operator_binding(ident, cred, bad, binding)
    assert not verify_operator_binding(ident, cred, GUARDIAN_KEY, b'')
    assert not verify_operator_binding(ident, b'', GUARDIAN_KEY, binding)


# --- the wire, and the un-bind path ------------------------------------------

def test_the_wire_form_of_declining_is_unchanged():
    """The opt-out is a byte-level guarantee, not a policy: a declining identity
    serializes to exactly what it did before these fields existed."""
    ident = _identity('plain')
    ident.sync_to_message()
    plain = ident.message.SerializeToString()

    ident.operator_pubkey = GUARDIAN_KEY
    ident.operator_key_binding = b'\xAB' * 64
    ident.sync_to_message()
    assert ident.message.SerializeToString() != plain

    # Un-binding returns to those exact bytes. `message` is reused between calls,
    # so this is a real hazard: without an explicit clear, a node that lost its
    # binding would keep advertising a guardian it no longer has.
    ident.operator_key_binding = b''
    ident.sync_to_message()
    assert ident.message.SerializeToString() == plain


def test_the_attestation_payload_carries_both_halves_or_neither():
    ident = _identity('carrier')
    ident.operator_pubkey = GUARDIAN_KEY
    ident.operator_key_binding = b'\xCD' * 48

    proc = SimpleNamespace(identity=ident)
    att = IdentityProcess._operator_attestation(proc)
    assert base64.b64decode(att['operator_pubkey']) == GUARDIAN_KEY
    assert base64.b64decode(att['operator_key_binding']) == b'\xCD' * 48

    peer = _identity('receiver')
    IdentityProcess._apply_operator_attestation(peer, att)
    assert peer.operator_pubkey == GUARDIAN_KEY
    assert peer.operator_key_binding == b'\xCD' * 48

    # Half is dropped on the way out...
    ident.operator_key_binding = b''
    assert 'operator_pubkey' not in IdentityProcess._operator_attestation(proc)
    # ...and a wrong-length key is dropped on the way in.
    bad = dict(att, operator_pubkey=base64.b64encode(
        GUARDIAN_KEY[:31]).decode('ascii'))
    peer2 = _identity('receiver2')
    IdentityProcess._apply_operator_attestation(peer2, bad)
    assert peer2.operator_pubkey == b''
    assert len(peer2.operator_key_binding) == 48   # the binding still arrived


def test_the_key_length_constant_is_an_ed25519_key():
    assert OPERATOR_PUBKEY_LEN == 32
