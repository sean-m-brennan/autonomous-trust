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
import base64
import hashlib
import logging
import uuid as uuid_mod
from types import SimpleNamespace

from autonomous_trust.core.identity.identity import (
    Identity, public_identity_to_canonical, public_identity_from_canonical)
from autonomous_trust.core.identity.idprocess import IdentityProcess
from autonomous_trust.core.identity.sign import Signature
from autonomous_trust.core.identity.encrypt import Encryptor
from autonomous_trust.core.identity.zta import (ZtaPolicy, ZtaResult, ZtaStatus,
                                                Verifier, BINDING_MODE_OFF)
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
    # The opt-in guardian-key check runs inside the operator-class branch of the
    # gate, so the stub needs it for any operator-credential case to reach the end.
    _verify_operator_key = IdentityProcess._verify_operator_key
    _zta_credentials = IdentityProcess._zta_credentials
    _zta_match_anchors = IdentityProcess._zta_match_anchors
    _zta_anchor_verifiers = IdentityProcess._zta_anchor_verifiers

    def __init__(self, peer_status=ZtaStatus.VERIFIED, operator_anchor=True,
                 operator_status=ZtaStatus.VERIFIED):
        # `binding_mode: off`: these fixtures carry no credential->identity binding,
        # and operator_bound classification is what is under test.
        self.configs = {ZtaPolicy.CONFIG_KEY: ZtaPolicy(
            enabled=True, require_at_admission=True,
            binding_mode=BINDING_MODE_OFF)}
        self._zta_policy_cache = None
        # Pre-seed caches so create_verifier (needs cryptography) is never called.
        self._zta_verifier_cache = _StubVerifier(peer_status)
        self._zta_operator_verifier_cache = (_StubVerifier(operator_status)
                                             if operator_anchor else False)
        # The gate walks the anchor list, so the peer stub must be seeded there.
        # Named 'peer' with operator=False on purpose: operator-class must be earned
        # through the DISTINCT operator verifier above, which is what these tests
        # exercise.
        self._zta_anchor_cache = [('peer', self._zta_verifier_cache, False)]
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


# ---------------------------------------------------------------------------
# Attended-now pull, responder side. The live session lives in the console
# app's address space; this process runs in its own subprocess and asks the
# main loop per pull, so these cases drive the round-trip state machine
# directly rather than relying on a mesh we cannot stand up in a unit test.
# ---------------------------------------------------------------------------
from autonomous_trust.core.identity.protocol import IdentityProtocol  # noqa: E402
from autonomous_trust.core.network import Message  # noqa: E402
from autonomous_trust.core.system import CfgIds  # noqa: E402
from autonomous_trust.core.config import from_json_string, to_json_string  # noqa: E402

NONCE = 'a1b2c3d4'


class _FakeQueue:
    def __init__(self, maxsize=0):
        self.items = []
        self._maxsize = maxsize

    def put(self, item, block=True, timeout=None):
        from queue import Full
        if self._maxsize and len(self.items) >= self._maxsize:
            raise Full()
        self.items.append(item)

    @property
    def last(self):
        return self.items[-1] if self.items else None


class _PullProc:
    """Stand-in carrying the real responder methods with an injectable clock."""
    _ATTEST_ROUND_TRIP_SEC = IdentityProcess._ATTEST_ROUND_TRIP_SEC
    handle_attest_request = IdentityProcess.handle_attest_request
    handle_operator_state_response = IdentityProcess.handle_operator_state_response
    _attest_payload = IdentityProcess._attest_payload
    _answer_attest_pull = IdentityProcess._answer_attest_pull
    _expire_attest_pending = IdentityProcess._expire_attest_pending
    _operator_attestation = IdentityProcess._operator_attestation

    def __init__(self, now=1000.0):
        self.name = CfgIds.identity
        self.identity = _operator_identity()
        self.identity.operator_attested_at = 0.0  # only a live pull may stamp it
        self.logger = logging.getLogger('test.pull')
        self.q_cadence = 0.01
        self._attest_pending = {}
        self._now = now

    def _now_epoch(self):
        return self._now

    def report_exception(self, err, function=None):
        raise AssertionError('unexpected exception in %s: %r' % (function, err))


def _queues():
    return {CfgIds.main: _FakeQueue(), CfgIds.network: _FakeQueue()}


def _pull(nonce=NONCE, requestor=None):
    payload = {'nonce': nonce} if nonce else {}
    return Message(CfgIds.identity, IdentityProtocol.attest_req,
                   to_json_string(payload), from_whom=requestor)


def _state_resp(attended=True, epoch=1721800500.0, have_session=True):
    return Message(CfgIds.identity, IdentityProtocol.operator_state_resp,
                   to_json_string({'attended': attended, 'epoch': epoch,
                                   'have_session': have_session}))


def test_pull_asks_the_main_loop_and_does_not_answer_inline():
    proc, queues = _PullProc(), _queues()
    assert proc.handle_attest_request(queues, _pull()) is True
    # Asked the main loop...
    assert queues[CfgIds.main].last.function == IdentityProtocol.operator_state_req
    # ...and did NOT block to answer: no reply on the wire yet.
    assert queues[CfgIds.network].items == []
    assert NONCE in proc._attest_pending


def test_attended_session_answers_with_the_reported_epoch():
    proc, queues = _PullProc(), _queues()
    proc.handle_attest_request(queues, _pull())
    proc.handle_operator_state_response(queues, _state_resp(epoch=1721800500.0))

    reply = queues[CfgIds.network].last
    assert reply.function == IdentityProtocol.attest_resp
    body = from_json_string(reply.obj)
    assert body['nonce'] == NONCE                     # bound to THIS request
    assert body['operator_attested_at'] == 1721800500.0
    assert body['operator_bound'] is True             # durable half rides along
    assert body['zta_issuer'] == ISSUER               # verifiable credential too
    assert not proc._attest_pending                   # pull retired


def test_unattended_session_answers_zero_explicitly():
    proc, queues = _PullProc(), _queues()
    proc.handle_attest_request(queues, _pull())
    proc.handle_operator_state_response(queues, _state_resp(attended=False))

    body = from_json_string(queues[CfgIds.network].last.obj)
    # An explicit 0 — "asked, nobody home" must not read as "didn't say".
    assert 'operator_attested_at' in body
    assert body['operator_attested_at'] == 0.0


def test_no_console_session_reads_as_unattended():
    proc, queues = _PullProc(), _queues()
    proc.handle_attest_request(queues, _pull())
    proc.handle_operator_state_response(
        queues, _state_resp(attended=False, epoch=0.0, have_session=False))
    body = from_json_string(queues[CfgIds.network].last.obj)
    assert body['operator_attested_at'] == 0.0


def test_attended_true_with_no_epoch_still_reads_unattended():
    # Defensive: 'attended' without a usable stamp cannot assert attendance.
    proc, queues = _PullProc(), _queues()
    proc.handle_attest_request(queues, _pull())
    proc.handle_operator_state_response(queues, _state_resp(epoch=0.0))
    body = from_json_string(queues[CfgIds.network].last.obj)
    assert body['operator_attested_at'] == 0.0


def test_unnonced_pull_is_refused_not_answered():
    # An attestation bound to nothing is replayable forever.
    proc, queues = _PullProc(), _queues()
    assert proc.handle_attest_request(queues, _pull(nonce=None)) is True
    assert proc._attest_pending == {}
    assert queues[CfgIds.main].items == []
    assert queues[CfgIds.network].items == []


def test_reply_is_addressed_to_the_pullers_identity_process():
    # net delivers by message.process. The answer goes to the puller's IDENTITY
    # process because that is the only one holding the operator trust anchor it
    # has to be checked against. (Contrast roster_resp, which is addressed to
    # the requestor-named process because ITS consumer is the main loop.)
    proc, queues = _PullProc(), _queues()
    proc.handle_attest_request(queues, _pull())
    proc.handle_operator_state_response(queues, _state_resp())
    assert queues[CfgIds.network].last.process == CfgIds.identity


def test_pull_times_out_as_unattended_rather_than_hanging():
    proc, queues = _PullProc(now=1000.0), _queues()
    proc.handle_attest_request(queues, _pull())

    proc._expire_attest_pending(queues)               # still inside the window
    assert queues[CfgIds.network].items == []
    assert NONCE in proc._attest_pending

    proc._now = 1000.0 + IdentityProcess._ATTEST_ROUND_TRIP_SEC
    proc._expire_attest_pending(queues)
    body = from_json_string(queues[CfgIds.network].last.obj)
    assert body['nonce'] == NONCE
    assert body['operator_attested_at'] == 0.0        # honest "cannot confirm"
    assert proc._attest_pending == {}


def test_expiry_is_a_noop_with_nothing_in_flight():
    proc, queues = _PullProc(), _queues()
    proc._expire_attest_pending(queues)
    assert queues[CfgIds.network].items == []


def test_backlogged_main_queue_leaves_the_pull_to_age_out():
    proc = _PullProc(now=1000.0)
    queues = {CfgIds.main: _FakeQueue(maxsize=1), CfgIds.network: _FakeQueue()}
    queues[CfgIds.main].put('occupied')
    proc.handle_attest_request(queues, _pull())       # Full is swallowed
    assert NONCE in proc._attest_pending              # recorded, so it can expire
    proc._now = 1003.0
    proc._expire_attest_pending(queues)
    assert from_json_string(queues[CfgIds.network].last.obj)['operator_attested_at'] == 0.0


def test_one_session_answer_serves_every_pull_in_flight():
    proc, queues = _PullProc(), _queues()
    proc.handle_attest_request(queues, _pull(nonce='n1'))
    proc.handle_attest_request(queues, _pull(nonce='n2'))
    proc.handle_operator_state_response(queues, _state_resp(epoch=1721800600.0))

    answered = {from_json_string(m.obj)['nonce']: from_json_string(m.obj)
                for m in queues[CfgIds.network].items}
    assert set(answered) == {'n1', 'n2'}
    assert all(b['operator_attested_at'] == 1721800600.0
               for b in answered.values())
    assert proc._attest_pending == {}


def test_handlers_ignore_other_verbs():
    proc, queues = _PullProc(), _queues()
    other = Message(CfgIds.identity, IdentityProtocol.roster_req, '')
    assert proc.handle_attest_request(queues, other) is False
    assert proc.handle_operator_state_response(queues, other) is False


# ---------------------------------------------------------------------------
# Main-loop side: the only part of the node that can actually see the console's
# session (the bridge runs run_forever in a thread of the app process), plus
# the requestor half of the pull.
# ---------------------------------------------------------------------------
from autonomous_trust.core.automate import AutonomousTrust  # noqa: E402


class _LoopProc:
    """Stand-in carrying the real main-loop attestation methods."""
    proc_name = CfgIds.main
    set_operator_session = AutonomousTrust.set_operator_session
    _operator_attended = AutonomousTrust._operator_attended
    _answer_operator_state = AutonomousTrust._answer_operator_state
    request_peer_attestation = AutonomousTrust.request_peer_attestation
    _consume_attest_resp = AutonomousTrust._consume_attest_resp
    _resolve_gateway = AutonomousTrust._resolve_gateway

    def __init__(self, session=None, peers=()):
        self.identity = _operator_identity()
        self._operator_session = session
        self._attest_sent = {}
        self.peer_attestations = {}
        self.logger = logging.getLogger('test.loop')
        self._peers = {str(p.uuid): p for p in peers}
        self.peers = SimpleNamespace(
            find_by_uuid=lambda u: self._peers.get(str(u)))


def _loop_queues():
    return {CfgIds.identity: _FakeQueue(), CfgIds.network: _FakeQueue()}


def test_loop_reports_absent_session_honestly():
    attended, epoch, have = _LoopProc(session=None)._operator_attended()
    assert (attended, epoch, have) == (False, 0.0, False)


def test_loop_reports_active_session_attended():
    attended, epoch, have = _LoopProc(
        session=_FakeSession(SessionState.ACTIVE))._operator_attended()
    assert attended is True and have is True and epoch > 0


def test_loop_reports_locked_session_unattended():
    attended, _epoch, have = _LoopProc(
        session=_FakeSession(SessionState.LOCKED))._operator_attended()
    assert attended is False and have is True


def test_loop_survives_a_broken_session():
    class _Angry:
        state = SessionState.ACTIVE

        def poll(self):
            raise RuntimeError('card reader on fire')

        def needs_reverify(self):
            return False

    attended, epoch, have = _LoopProc(session=_Angry())._operator_attended()
    # A session we cannot read is not an attended one, and must not raise.
    assert (attended, epoch, have) == (False, 0.0, False)


def test_loop_answers_operator_state_query_on_the_identity_queue():
    proc = _LoopProc(session=_FakeSession(SessionState.ACTIVE))
    queues = _loop_queues()
    proc._answer_operator_state(queues, Message(
        CfgIds.main, IdentityProtocol.operator_state_req, ''))

    reply = queues[CfgIds.identity].last
    assert reply.function == IdentityProtocol.operator_state_resp
    body = from_json_string(reply.obj)
    assert body['attended'] is True and body['have_session'] is True
    assert body['epoch'] > 0
    # Local-only IPC: this must never reach the wire.
    assert queues[CfgIds.network].items == []


def test_request_peer_attestation_hands_off_to_the_identity_process():
    # The main loop does NOT pull: verification needs the operator anchor, which
    # only the identity process holds. This is the local hand-off.
    peer = _plain_identity()
    proc, queues = _LoopProc(peers=[peer]), _loop_queues()
    assert proc.request_peer_attestation(queues, str(peer.uuid)) is True

    req = queues[CfgIds.identity].last
    assert req.function == IdentityProtocol.attest_trigger
    assert from_json_string(req.obj)['target'] == str(peer.uuid)
    assert str(peer.uuid) in proc._attest_sent
    # Local-only verb: the main loop never puts this on the wire itself.
    assert queues[CfgIds.network].items == []


def test_request_peer_attestation_accepts_an_identity_or_a_uuid():
    peer = _plain_identity()
    proc, queues = _LoopProc(peers=[peer]), _loop_queues()
    assert proc.request_peer_attestation(queues, peer) is True
    assert from_json_string(queues[CfgIds.identity].last.obj)['target'] == str(peer.uuid)


def test_consume_attest_resp_records_a_verified_stamp():
    peer = _plain_identity()
    proc, queues = _LoopProc(peers=[peer]), _loop_queues()
    proc.request_peer_attestation(queues, str(peer.uuid))

    proc._consume_attest_resp(queues, Message(
        CfgIds.main, IdentityProtocol.attest_resp,
        to_json_string({'peer': str(peer.uuid), 'operator_verified': True,
                        'operator_attested_at': 1721800700.0})))

    assert proc.peer_attestations[str(peer.uuid)] == 1721800700.0
    assert str(peer.uuid) not in proc._attest_sent      # pull retired


def test_consume_attest_resp_drops_a_report_we_never_asked_for():
    # Nothing should be able to inject an attendance claim for a peer this node
    # never pulled.
    proc, queues = _LoopProc(), _loop_queues()
    proc._consume_attest_resp(queues, Message(
        CfgIds.main, IdentityProtocol.attest_resp,
        to_json_string({'peer': 'uuid-stranger',
                        'operator_attested_at': 9999.0})))
    assert proc.peer_attestations == {}


def test_consume_attest_resp_treats_a_missing_stamp_as_unattended():
    peer = _plain_identity()
    proc, queues = _LoopProc(peers=[peer]), _loop_queues()
    proc.request_peer_attestation(queues, str(peer.uuid))
    proc._consume_attest_resp(queues, Message(
        CfgIds.main, IdentityProtocol.attest_resp,
        to_json_string({'peer': str(peer.uuid), 'operator_verified': False})))
    assert proc.peer_attestations[str(peer.uuid)] == 0.0


def test_loop_set_operator_session_seam():
    proc = _LoopProc()
    sess = _FakeSession()
    proc.set_operator_session(sess)
    assert proc._operator_session is sess


def test_round_trip_end_to_end_across_the_process_boundary():
    """The whole point: a pull answered from a session the responder cannot see.

    Wires the identity-side responder to the main-loop-side session holder by
    hand — the two really do run in different processes, so this is as close to
    the live path as a unit test gets.
    """
    puller = _plain_identity()
    responder = _PullProc()
    loop = _LoopProc(session=_FakeSession(SessionState.ACTIVE))
    queues = {CfgIds.main: _FakeQueue(), CfgIds.network: _FakeQueue(),
              CfgIds.identity: _FakeQueue()}

    # 1. pull arrives at the identity subprocess; it asks the main loop.
    responder.handle_attest_request(queues, _pull(requestor=puller))
    assert queues[CfgIds.main].last.function == IdentityProtocol.operator_state_req

    # 2. the main loop reads the console session and answers.
    loop._answer_operator_state(queues, queues[CfgIds.main].last)

    # 3. the identity subprocess stamps and replies to the puller.
    responder.handle_operator_state_response(queues, queues[CfgIds.identity].last)

    body = from_json_string(queues[CfgIds.network].last.obj)
    assert body['nonce'] == NONCE
    assert body['operator_attested_at'] > 0        # a human IS at the console
    assert body['operator_bound'] is True


# ---------------------------------------------------------------------------
# Requestor side, in the identity process — because verifying the answer needs
# the operator trust anchor, which lives here beside the admission gate. These
# cases are the security core of the feature: what a peer ASSERTS never becomes
# what this node RECORDS without passing the nonce, credential and window
# checks.
# ---------------------------------------------------------------------------

class _ReqProc:
    """Stand-in carrying the real requestor methods, with the operator gate
    wired to a stub verifier (as _OpGateProc does) and an injectable clock."""
    _ATTEST_REPLY_WAIT_SEC = IdentityProcess._ATTEST_REPLY_WAIT_SEC
    _ATTEST_WINDOW_SEC = IdentityProcess._ATTEST_WINDOW_SEC
    handle_attest_trigger = IdentityProcess.handle_attest_trigger
    handle_attest_response = IdentityProcess.handle_attest_response
    _report_attestation = IdentityProcess._report_attestation
    _store_peer_attestation = IdentityProcess._store_peer_attestation
    _expire_attest_sent = IdentityProcess._expire_attest_sent
    _apply_operator_attestation = staticmethod(IdentityProcess._apply_operator_attestation)
    _is_operator_credential = IdentityProcess._is_operator_credential
    _zta_operator_verifier = IdentityProcess._zta_operator_verifier
    _zta_policy = IdentityProcess._zta_policy
    _mark_operator_bound = staticmethod(IdentityProcess._mark_operator_bound)

    def __init__(self, peers=(), now=1721800000.0, operator_anchor=True,
                 operator_status=ZtaStatus.VERIFIED):
        self.name = CfgIds.identity
        self.identity = _operator_identity()
        self.logger = logging.getLogger('test.req')
        self.q_cadence = 0.01
        self._attest_sent = {}
        self._now = now
        self.configs = {ZtaPolicy.CONFIG_KEY: ZtaPolicy(enabled=True,
                                                        require_at_admission=True)}
        self._zta_policy_cache = None
        self._zta_operator_verifier_cache = (_StubVerifier(operator_status)
                                             if operator_anchor else False)
        self._peers = {str(p.uuid): p for p in peers}
        self.peers = SimpleNamespace(
            find_by_uuid=lambda u: self._peers.get(str(u)),
            all=list(peers))

    def _now_epoch(self):
        return self._now

    def report_exception(self, err, function=None):
        raise AssertionError('unexpected exception in %s: %r' % (function, err))


def _req_queues():
    return {CfgIds.main: _FakeQueue(), CfgIds.network: _FakeQueue()}


def _stored_peer(nickname='target'):
    """A peer as this node has it stored — attested_at frozen at whatever
    admission captured, which is exactly the staleness this feature fixes.
    A real Identity, since routing (to_whom) requires one."""
    peer = Identity(uuid_mod.uuid4(), '10.0.0.9', nickname,
                    Signature.generate(), Encryptor.generate(), 'petTg', False)
    peer.operator_attested_at = 0.0
    peer.operator_bound = False
    return peer


def _trigger(target):
    return Message(CfgIds.identity, IdentityProtocol.attest_trigger,
                   to_json_string({'target': str(target)}))


def _peer_answer(nonce, attested_at, cred=CRED, cred_hash=None,
                 responder=None, bound=True):
    """An attest_resp as it arrives off the wire from the peer."""
    body = {'nonce': nonce, 'operator_attested_at': attested_at}
    if bound:
        body['operator_bound'] = True
    if cred is not None:
        body['zta_credential'] = base64.b64encode(cred).decode('ascii')
        digest = hashlib.sha256(cred).digest() if cred_hash is None else cred_hash
        body['zta_credential_hash'] = base64.b64encode(digest).decode('ascii')
        body['zta_issuer'] = ISSUER
    return Message(CfgIds.identity, IdentityProtocol.attest_resp,
                   to_json_string(body), from_whom=responder)


def test_trigger_emits_a_nonced_wire_query_to_the_peer():
    peer = _stored_peer()
    proc, queues = _ReqProc(peers=[peer]), _req_queues()
    assert proc.handle_attest_trigger(queues, _trigger(peer.uuid)) is True

    req = queues[CfgIds.network].last
    assert req.function == IdentityProtocol.attest_req
    assert req.process == CfgIds.identity       # peer's identity process answers
    nonce = from_json_string(req.obj)['nonce']
    assert nonce and proc._attest_sent[nonce][0] == str(peer.uuid)


def test_trigger_mints_a_fresh_nonce_every_time():
    peer = _stored_peer()
    proc, queues = _ReqProc(peers=[peer]), _req_queues()
    proc.handle_attest_trigger(queues, _trigger(peer.uuid))
    proc.handle_attest_trigger(queues, _trigger(peer.uuid))
    nonces = [from_json_string(m.obj)['nonce'] for m in queues[CfgIds.network].items]
    # A reused nonce would make a captured answer valid for the next pull too.
    assert len(set(nonces)) == 2


def test_trigger_on_unroutable_peer_answers_the_consumer_immediately():
    proc, queues = _ReqProc(), _req_queues()
    proc.handle_attest_trigger(queues, _trigger('uuid-nobody'))
    assert queues[CfgIds.network].items == []
    body = from_json_string(queues[CfgIds.main].last.obj)
    assert body['peer'] == 'uuid-nobody'
    assert body['operator_attested_at'] == 0.0
    assert body['operator_verified'] is False


def _pull_and_answer(answer_fn, **proc_kw):
    peer = _stored_peer()
    proc = _ReqProc(peers=[peer], **proc_kw)
    queues = _req_queues()
    proc.handle_attest_trigger(queues, _trigger(peer.uuid))
    nonce = from_json_string(queues[CfgIds.network].last.obj)['nonce']
    proc.handle_attest_response(queues, answer_fn(nonce, peer))
    return proc, peer, queues


def test_verified_in_window_stamp_is_recorded_and_reported():
    fresh = 1721800000.0
    proc, peer, queues = _pull_and_answer(
        lambda n, p: _peer_answer(n, fresh, responder=p))

    # The local peer mirror now carries a LIVE value — the gap this closes.
    assert peer.operator_attested_at == fresh
    assert peer.operator_bound is True
    body = from_json_string(queues[CfgIds.main].last.obj)
    assert body['peer'] == str(peer.uuid)
    assert body['operator_attested_at'] == fresh
    assert body['operator_verified'] is True
    assert proc._attest_sent == {}              # retired: not replayable


def test_unknown_nonce_is_dropped_entirely():
    peer = _stored_peer()
    proc, queues = _ReqProc(peers=[peer]), _req_queues()
    proc.handle_attest_trigger(queues, _trigger(peer.uuid))
    proc.handle_attest_response(
        queues, _peer_answer('never-minted', 1721800000.0, responder=peer))

    # Nothing recorded, nothing reported, and our real pull stays open.
    assert peer.operator_attested_at == 0.0
    assert queues[CfgIds.main].items == []
    assert len(proc._attest_sent) == 1


def test_replayed_answer_is_refused_on_the_second_use():
    """The heart of attended-NOW: an answer is good exactly once.

    Without this, a node could record one attested response and re-present it
    forever to claim a human is standing by.
    """
    fresh = 1721800000.0
    proc, peer, queues = _pull_and_answer(
        lambda n, p: _peer_answer(n, fresh, responder=p))
    assert peer.operator_attested_at == fresh          # first use worked

    used_nonce = from_json_string(queues[CfgIds.network].last.obj)['nonce']
    peer.operator_attested_at = 0.0                    # clock moves on
    reported = len(queues[CfgIds.main].items)

    # Re-present the exact answer that just succeeded.
    proc.handle_attest_response(
        queues, _peer_answer(used_nonce, fresh, responder=peer))

    assert peer.operator_attested_at == 0.0            # refused
    assert len(queues[CfgIds.main].items) == reported   # nothing re-reported


def test_right_nonce_from_the_wrong_node_is_refused():
    imposter = _stored_peer('imposter')
    proc, peer, queues = _pull_and_answer(
        lambda n, p: _peer_answer(n, 1721800000.0, responder=imposter))
    assert peer.operator_attested_at == 0.0
    body = from_json_string(queues[CfgIds.main].last.obj)
    assert body['peer'] == str(peer.uuid) and body['operator_verified'] is False


def test_non_operator_credential_records_unattended():
    # Chain-valid for the mission anchor but NOT operator-class.
    proc, peer, queues = _pull_and_answer(
        lambda n, p: _peer_answer(n, 1721800000.0, responder=p),
        operator_status=ZtaStatus.REJECTED)
    assert peer.operator_attested_at == 0.0
    assert peer.operator_bound is False
    body = from_json_string(queues[CfgIds.main].last.obj)
    assert body['operator_verified'] is False
    assert body['operator_attested_at'] == 0.0


def test_credential_hash_mismatch_records_unattended():
    # Advertised hash disagrees with the credential bytes actually sent.
    proc, peer, queues = _pull_and_answer(
        lambda n, p: _peer_answer(n, 1721800000.0, responder=p,
                                  cred_hash=b'\x00' * 32))
    assert peer.operator_attested_at == 0.0
    assert from_json_string(queues[CfgIds.main].last.obj)['operator_verified'] is False


def test_missing_credential_records_unattended():
    proc, peer, queues = _pull_and_answer(
        lambda n, p: _peer_answer(n, 1721800000.0, cred=None, responder=p))
    assert peer.operator_attested_at == 0.0


def test_no_operator_anchor_configured_is_failsafe():
    proc, peer, queues = _pull_and_answer(
        lambda n, p: _peer_answer(n, 1721800000.0, responder=p),
        operator_anchor=False)
    assert peer.operator_attested_at == 0.0
    assert from_json_string(queues[CfgIds.main].last.obj)['operator_verified'] is False


def test_far_future_stamp_is_refused():
    # A peer cannot mint permanent freshness by stamping ahead of our clock.
    proc, peer, queues = _pull_and_answer(
        lambda n, p: _peer_answer(n, 1721800000.0 + 86400.0, responder=p))
    assert peer.operator_attested_at == 0.0
    body = from_json_string(queues[CfgIds.main].last.obj)
    assert body['operator_attested_at'] == 0.0
    # The credential DID verify — the peer is operator-bound, just not attended.
    assert body['operator_verified'] is True
    assert peer.operator_bound is True


def test_ancient_stamp_is_refused():
    proc, peer, queues = _pull_and_answer(
        lambda n, p: _peer_answer(n, 1721800000.0 - 86400.0, responder=p))
    assert peer.operator_attested_at == 0.0
    assert from_json_string(queues[CfgIds.main].last.obj)['operator_attested_at'] == 0.0


def test_stamp_at_the_window_edge_is_accepted():
    edge = 1721800000.0 - IdentityProcess._ATTEST_WINDOW_SEC
    proc, peer, queues = _pull_and_answer(
        lambda n, p: _peer_answer(n, edge, responder=p))
    assert peer.operator_attested_at == edge


def test_peer_reporting_zero_is_a_clean_unattended_answer():
    proc, peer, queues = _pull_and_answer(
        lambda n, p: _peer_answer(n, 0.0, responder=p))
    assert peer.operator_attested_at == 0.0
    body = from_json_string(queues[CfgIds.main].last.obj)
    assert body['operator_attested_at'] == 0.0
    # Verified operator hardware, just nobody at the console.
    assert body['operator_verified'] is True
    assert peer.operator_bound is True


def test_unanswered_pull_resolves_as_unattended():
    peer = _stored_peer()
    proc, queues = _ReqProc(peers=[peer], now=1000.0), _req_queues()
    proc.handle_attest_trigger(queues, _trigger(peer.uuid))

    proc._expire_attest_sent(queues)                  # still inside the window
    assert queues[CfgIds.main].items == []

    proc._now = 1000.0 + IdentityProcess._ATTEST_REPLY_WAIT_SEC
    proc._expire_attest_sent(queues)
    body = from_json_string(queues[CfgIds.main].last.obj)
    assert body['peer'] == str(peer.uuid)
    assert body['operator_attested_at'] == 0.0        # a silent node is unattended
    assert proc._attest_sent == {}


def test_requestor_expiry_is_a_noop_with_nothing_in_flight():
    proc, queues = _ReqProc(), _req_queues()
    proc._expire_attest_sent(queues)
    assert queues[CfgIds.main].items == []


def test_requestor_handlers_ignore_other_verbs():
    proc, queues = _ReqProc(), _req_queues()
    other = Message(CfgIds.identity, IdentityProtocol.roster_req, '')
    assert proc.handle_attest_trigger(queues, other) is False
    assert proc.handle_attest_response(queues, other) is False


def test_verified_answer_for_an_unstored_peer_still_reports():
    # We pulled a peer we can route to but do not hold in the roster: the
    # consumer must still get its answer.
    peer = _stored_peer()
    proc, queues = _ReqProc(peers=[peer]), _req_queues()
    proc.handle_attest_trigger(queues, _trigger(peer.uuid))
    nonce = from_json_string(queues[CfgIds.network].last.obj)['nonce']
    proc._peers.clear()
    proc.handle_attest_response(queues, _peer_answer(nonce, 1721800000.0))
    assert from_json_string(queues[CfgIds.main].last.obj)['operator_attested_at'] == 1721800000.0
