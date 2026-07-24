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
"""Unit coverage for the operator-attended signal (ethne guardian edge, D8/Q9).

P-L1 — the data model + signed-payload carriage:
  * the two new Identity fields (operator_bound, operator_attested_at) survive
    the protobuf sync round-trip and the DRY-canonical (peer_accepted) form;
  * they are excluded from identity equality (rotation/attestation must not
    change identity);
  * a plain (non-operator) peer's canonical form is byte-identical to before
    (backward-compat for existing peer bundles);
  * the request_access attestation encode/decode helpers round-trip the ZTA
    binding onto a newly-announced peer, and tolerate a missing/2-element
    payload.

See lib/muudd/lib/ethne/doc/design.md and doc/architecture/operator-access.md.
"""
import hashlib
import logging
import uuid as uuid_mod
from types import SimpleNamespace

from autonomous_trust.core.identity.identity import (
    Identity, public_identity_to_canonical, public_identity_from_canonical)
from autonomous_trust.core.identity.idprocess import IdentityProcess
from autonomous_trust.core.identity.sign import Signature
from autonomous_trust.core.identity.encrypt import Encryptor
from autonomous_trust.core.identity.zta import ZtaPolicy, ZtaResult, ZtaStatus, Verifier
from autonomous_trust.core.protobuf.identity import identity_pb2

CRED = b'FAKE-OPERATOR-DER-CERT'
CRED_HASH = hashlib.sha256(CRED).digest()
ISSUER = 'PIV:CN=Jane Operator'
ATTESTED = 1721800000.0

# Byte-shape of the canonical PUBLIC identity form BEFORE this feature — a
# non-operator peer must still emit exactly this key set.
BASE_CANONICAL_KEYS = {'typename', 'uuid', 'address', 'nickname',
                       'signature', 'encryptor'}


def _operator_identity():
    return Identity(uuid_mod.uuid4(), '10.0.0.5', 'node-op',
                    Signature.generate(), Encryptor.generate(), 'petOp', False,
                    zta_credential=CRED, zta_issuer=ISSUER,
                    zta_credential_hash=CRED_HASH,
                    operator_bound=True, operator_attested_at=ATTESTED)


def _plain_identity():
    return Identity(uuid_mod.uuid4(), '10.0.0.6', 'node-plain',
                    Signature.generate(), Encryptor.generate(), 'petPl', False)


def test_defaults_are_unattended():
    ident = _plain_identity()
    assert ident.operator_bound is False
    assert ident.operator_attested_at == 0.0


def test_protobuf_sync_roundtrip_preserves_signal():
    ident = _operator_identity()
    ident.sync_to_message()
    raw = ident.message.SerializeToString()
    clone = Identity.__new__(Identity)
    clone.message = identity_pb2.Identity()
    clone.message.ParseFromString(raw)
    clone.sync_from_message()
    assert clone.operator_bound is True
    assert clone.operator_attested_at == ATTESTED
    assert clone.zta_credential == CRED
    assert clone.zta_credential_hash == CRED_HASH
    assert clone.zta_issuer == ISSUER


def test_canonical_roundtrip_preserves_signal():
    pub = _operator_identity().publish()
    canonical = public_identity_to_canonical(pub)
    assert canonical['operator_bound'] is True
    assert canonical['operator_attested_at'] == ATTESTED
    back = public_identity_from_canonical(canonical)
    assert back.operator_bound is True
    assert back.operator_attested_at == ATTESTED
    assert back.zta_credential == CRED
    assert back.zta_credential_hash == CRED_HASH
    assert back.zta_issuer == ISSUER


def test_attestation_excluded_from_equality():
    op = _operator_identity().publish()
    # Same uuid/keys/address/nickname, no attestation -> still equal.
    plain = Identity(op.uuid, op.address, op.nickname,
                     op.signature, op.encryptor, op.petname)
    assert plain == op
    assert op == plain


def test_non_operator_canonical_is_backward_compatible():
    canonical = public_identity_to_canonical(_plain_identity().publish())
    assert set(canonical.keys()) == BASE_CANONICAL_KEYS


def test_apply_operator_attestation_roundtrips_binding():
    # A freshly-announced peer identity (no zta binding on the envelope) gets
    # the wire-delivered attestation copied onto it before admission.
    peer = _plain_identity()
    att = IdentityProcess.__dict__  # sanity: helpers exist on the class
    assert '_apply_operator_attestation' in att
    assert '_operator_attestation' in att

    source = _operator_identity()

    # Build the attestation the way _operator_attestation does, via a stub with
    # just the identity attribute (the method only reads self.identity).
    class _Stub:
        identity = source
    encoded = IdentityProcess._operator_attestation(_Stub())
    assert encoded['operator_bound'] is True
    assert encoded['zta_issuer'] == ISSUER

    IdentityProcess._apply_operator_attestation(peer, encoded)
    assert peer.zta_credential == CRED
    assert peer.zta_credential_hash == CRED_HASH
    assert peer.zta_issuer == ISSUER
    # advertised claim copied (authoritative overwrite happens later in _zta_admit)
    assert peer.operator_bound is True
    assert peer.operator_attested_at == ATTESTED


def test_apply_operator_attestation_tolerates_empty_and_malformed():
    peer = _plain_identity()
    IdentityProcess._apply_operator_attestation(peer, {})
    assert peer.operator_bound is False
    assert peer.zta_credential == b''
    # malformed base64 -> treated as absent, no raise
    IdentityProcess._apply_operator_attestation(
        peer, {'zta_credential': '!!!not-base64!!!', 'operator_bound': True})
    assert peer.zta_credential == b''


def test_plain_node_emits_two_element_attestation_empty():
    # A node with no operator binding contributes an empty attestation dict,
    # so the request_access payload stays backward-compatible.
    class _Stub:
        identity = _plain_identity()
    assert IdentityProcess._operator_attestation(_Stub()) == {}


# --------------------------------------------------------------------------- #
# P-L2 — receiver sets operator_bound authoritatively (operator-class = chain-
# verifies against the DISTINCT operator anchor). These exercise the decision
# logic with STUB verifiers so they run without `cryptography` (the real-cert
# path is gated the same way as test_zta_admission and runs under the full
# toolchain / conformance).
# --------------------------------------------------------------------------- #
DRONE_CRED = b'FAKE-DRONE-DER-CERT'
DRONE_HASH = hashlib.sha256(DRONE_CRED).digest()


class _StubVerifier(Verifier):
    """Verifier that returns a fixed status; check_revocation always clean."""
    def __init__(self, status=ZtaStatus.VERIFIED):
        self._status = status

    def verify_credential(self, cred_data):
        if not cred_data:
            return ZtaResult.set(ZtaStatus.REJECTED, 'no credential')
        return ZtaResult.set(self._status, '', hashlib.sha256(cred_data).digest())

    def check_revocation(self, credential_hash):
        return ZtaResult.set(ZtaStatus.UNAVAILABLE, 'no CRL')


class _OpGateProc:
    """Stand-in carrying the real gate methods with injectable verifiers."""
    _zta_policy = IdentityProcess._zta_policy
    _zta_verifier = IdentityProcess._zta_verifier
    _zta_operator_verifier = IdentityProcess._zta_operator_verifier
    _zta_admit = IdentityProcess._zta_admit
    _zta_credential_replayed = IdentityProcess._zta_credential_replayed
    _is_operator_credential = IdentityProcess._is_operator_credential
    _mark_operator_bound = staticmethod(IdentityProcess._mark_operator_bound)

    def __init__(self, peer_status=ZtaStatus.VERIFIED, operator_anchor=True,
                 operator_status=ZtaStatus.VERIFIED):
        self.configs = {ZtaPolicy.CONFIG_KEY: ZtaPolicy(enabled=True,
                                                        require_at_admission=True)}
        self._zta_policy_cache = None
        # Pre-seed caches so create_verifier (needs cryptography) is never called.
        self._zta_verifier_cache = _StubVerifier(peer_status)
        self._zta_operator_verifier_cache = (_StubVerifier(operator_status)
                                             if operator_anchor else False)
        self._zta_capped = set()
        self._operator_verified = set()
        self.logger = logging.getLogger('test.operator')
        self.peers = SimpleNamespace(all=[])
        self.identity = None


def _admit_peer(cred=DRONE_CRED, advertised_hash=None, advertised_bound=False,
                **proc_kw):
    proc = _OpGateProc(**proc_kw)
    peer = SimpleNamespace(
        zta_credential=cred,
        zta_credential_hash=DRONE_HASH if advertised_hash is None else advertised_hash,
        zta_issuer='PIV:CN=whoever',
        operator_bound=advertised_bound,
        operator_attested_at=0.0,
        nickname='newbie', uuid='uuid-newbie')
    decision = proc._zta_admit(peer)
    return proc, peer, decision


def test_operator_credential_sets_bound_true():
    proc, peer, decision = _admit_peer(operator_status=ZtaStatus.VERIFIED)
    assert decision == 'admit'
    assert peer.operator_bound is True
    assert peer.uuid in proc._operator_verified


def test_device_credential_stays_bound_false():
    # Verifies against the mission anchor but NOT the operator anchor -> drone.
    proc, peer, decision = _admit_peer(operator_status=ZtaStatus.REJECTED)
    assert decision == 'admit'
    assert peer.operator_bound is False
    assert peer.uuid not in proc._operator_verified


def test_lying_node_operator_claim_overwritten():
    # Node advertises operator_bound=True but its credential is NOT operator-class.
    proc, peer, decision = _admit_peer(advertised_bound=True,
                                       operator_status=ZtaStatus.REJECTED)
    assert decision == 'admit'
    assert peer.operator_bound is False


def test_no_operator_anchor_configured_is_failsafe_false():
    proc, peer, decision = _admit_peer(advertised_bound=True, operator_anchor=False)
    assert decision == 'admit'
    assert peer.operator_bound is False


def test_advertised_hash_mismatch_blocks_operator_class():
    # Credential is operator-class at the anchor, but the advertised hash lies.
    proc, peer, decision = _admit_peer(advertised_hash=b'\x00' * 32,
                                       operator_status=ZtaStatus.VERIFIED)
    assert decision == 'admit'
    assert peer.operator_bound is False


def test_disabled_policy_neutralizes_advertised_bound():
    proc = _OpGateProc()
    proc.configs = {ZtaPolicy.CONFIG_KEY: ZtaPolicy(enabled=False)}
    proc._zta_policy_cache = None
    peer = SimpleNamespace(zta_credential=DRONE_CRED, zta_credential_hash=DRONE_HASH,
                           operator_bound=True, operator_attested_at=0.0,
                           nickname='x', uuid='uuid-x')
    assert proc._zta_admit(peer) == 'admit'
    assert peer.operator_bound is False


# --------------------------------------------------------------------------- #
# P-L3 — attended-now seam: self-stamp operator_attested_at from a live session
# on (re)announce; durable operator_bound set at activation.
# --------------------------------------------------------------------------- #
from autonomous_trust.core.identity.zta import ZtaStatus as _Zs  # noqa: E402  (keep imports grouped)
from autonomous_trust.core.operator.session import SessionState


class _FakeSession:
    def __init__(self, state=SessionState.ACTIVE, reverify=False):
        self.state = state
        self._reverify = reverify
        self.polled = False

    def poll(self):
        self.polled = True

    def needs_reverify(self):
        return self._reverify


class _RefreshProc:
    _refresh_operator_attestation = IdentityProcess._refresh_operator_attestation
    set_operator_session = IdentityProcess.set_operator_session

    def __init__(self, session=None, now=1000.0):
        self.identity = _operator_identity()
        self.identity.operator_attested_at = 0.0
        self._operator_session = session
        self.logger = logging.getLogger('test.refresh')
        self._now = now

    def _now_epoch(self):
        return self._now


def test_refresh_no_session_is_noop():
    proc = _RefreshProc(session=None)
    proc.identity.operator_attested_at = 123.0
    proc._refresh_operator_attestation()
    assert proc.identity.operator_attested_at == 123.0  # untouched


def test_refresh_active_session_stamps_now():
    proc = _RefreshProc(session=_FakeSession(SessionState.ACTIVE), now=1721800500.0)
    proc._refresh_operator_attestation()
    assert proc._operator_session.polled is True
    assert proc.identity.operator_attested_at == 1721800500.0


def test_refresh_locked_session_clears_stamp():
    proc = _RefreshProc(session=_FakeSession(SessionState.LOCKED), now=999.0)
    proc.identity.operator_attested_at = 42.0
    proc._refresh_operator_attestation()
    assert proc.identity.operator_attested_at == 0.0


def test_refresh_stale_reverify_clears_stamp():
    proc = _RefreshProc(session=_FakeSession(SessionState.ACTIVE, reverify=True))
    proc.identity.operator_attested_at = 42.0
    proc._refresh_operator_attestation()
    assert proc.identity.operator_attested_at == 0.0


def test_set_operator_session_seam():
    proc = _RefreshProc(session=None)
    sess = _FakeSession()
    proc.set_operator_session(sess)
    assert proc._operator_session is sess


def test_bind_piv_credential_sets_durable_operator_bound():
    from autonomous_trust.core.operator.activate import bind_piv_credential
    ident = _plain_identity()
    assert ident.operator_bound is False
    bind_piv_credential(ident, b'ANY-DER-BYTES')
    assert ident.operator_bound is True
    assert ident.operator_attested_at == 0.0  # freshness is NOT set at binding
