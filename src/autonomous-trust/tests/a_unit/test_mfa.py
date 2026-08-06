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
"""Unit tests for the MFA chain combinator (PIV_MFA_OPERATOR_ACCESS_PLAN.md §7)."""
from autonomous_trust.core.identity.zta import (
    MfaChain, CombinePolicy, MfaCredential, NullVerifier, Verifier,
    ZtaResult, ZtaStatus)


class _FixedVerifier(Verifier):
    """A verifier that returns a preset result, with a stable hash."""

    def __init__(self, status, reason='', cred_hash=b'', available=True,
                 secondary=False):
        self._status = status
        self._reason = reason
        self._hash = cred_hash
        self._available = available
        self.secondary_factor = secondary
        self.seen = []  # credentials this factor was asked to verify

    def verify_credential(self, cred_data):
        self.seen.append(cred_data)
        return ZtaResult(status=self._status, reason=self._reason,
                         credential_hash=self._hash)

    def is_available(self):
        return self._available


_PRIMARY = b'\x01' * 32
_SECOND = b'\x02' * 32


class TestMfaChainAnd:
    def test_all_verified(self):
        chain = MfaChain([_FixedVerifier(ZtaStatus.VERIFIED, cred_hash=_PRIMARY),
                          _FixedVerifier(ZtaStatus.VERIFIED, cred_hash=_SECOND)])
        r = chain.verify_credential(b'cred')
        assert r.status is ZtaStatus.VERIFIED
        # Hash passthrough: combined hash is the PRIMARY (first) factor's.
        assert r.credential_hash == _PRIMARY

    def test_hash_is_primary_even_when_rejected_later(self):
        # A second-factor rejection still binds to the primary identity hash.
        chain = MfaChain([_FixedVerifier(ZtaStatus.VERIFIED, cred_hash=_PRIMARY),
                          _FixedVerifier(ZtaStatus.REJECTED, cred_hash=_SECOND)])
        r = chain.verify_credential(b'cred')
        assert r.status is ZtaStatus.REJECTED
        assert r.credential_hash == _PRIMARY

    def test_first_hard_fail_short_circuits(self):
        # A REJECTED primary short-circuits; the EXPIRED second is never reached.
        reached = {'second': False}

        class _Tracking(Verifier):
            def verify_credential(self, cred_data):
                reached['second'] = True
                return ZtaResult.set(ZtaStatus.EXPIRED)

        chain = MfaChain([_FixedVerifier(ZtaStatus.REJECTED, cred_hash=_PRIMARY),
                          _Tracking()])
        r = chain.verify_credential(b'cred')
        assert r.status is ZtaStatus.REJECTED
        assert reached['second'] is False

    def test_status_precedence_expired_and_revoked_short_circuit(self):
        for bad in (ZtaStatus.EXPIRED, ZtaStatus.REVOKED):
            chain = MfaChain([_FixedVerifier(bad, cred_hash=_PRIMARY),
                              _FixedVerifier(ZtaStatus.VERIFIED, cred_hash=_SECOND)])
            assert chain.verify_credential(b'cred').status is bad

    def test_deferred_downgrades_not_rejects(self):
        # DEFERRED/UNAVAILABLE -> DEFERRED (fail-safe handoff), not REJECTED.
        for soft in (ZtaStatus.DEFERRED, ZtaStatus.UNAVAILABLE):
            chain = MfaChain([_FixedVerifier(ZtaStatus.VERIFIED, cred_hash=_PRIMARY),
                              _FixedVerifier(soft, cred_hash=_SECOND)])
            r = chain.verify_credential(b'cred')
            assert r.status is ZtaStatus.DEFERRED
            assert r.credential_hash == _PRIMARY

    def test_hard_fail_beats_deferred(self):
        # Order matters: a soft factor before a hard fail still rejects.
        chain = MfaChain([_FixedVerifier(ZtaStatus.VERIFIED, cred_hash=_PRIMARY),
                          _FixedVerifier(ZtaStatus.DEFERRED, cred_hash=_SECOND),
                          _FixedVerifier(ZtaStatus.REJECTED, cred_hash=b'\x03' * 32)])
        assert chain.verify_credential(b'cred').status is ZtaStatus.REJECTED

    def test_empty_chain_rejected(self):
        assert MfaChain([]).verify_credential(b'cred').status is ZtaStatus.REJECTED

    def test_single_null_factor_is_no_op_verified(self):
        # The P0 default chain: MfaChain([NullVerifier]) always verifies.
        chain = MfaChain([NullVerifier()])
        assert chain.verify_credential(b'cred').status is ZtaStatus.VERIFIED

    def test_is_available_is_and(self):
        assert MfaChain([_FixedVerifier(ZtaStatus.VERIFIED, available=True),
                         _FixedVerifier(ZtaStatus.VERIFIED, available=True)
                         ]).is_available() is True
        assert MfaChain([_FixedVerifier(ZtaStatus.VERIFIED, available=True),
                         _FixedVerifier(ZtaStatus.VERIFIED, available=False)
                         ]).is_available() is False
        assert MfaChain([]).is_available() is False

    def test_credential_hash_delegates_to_primary(self):
        chain = MfaChain([NullVerifier()])
        # NullVerifier hashes via the base SHA-256; chain mirrors the primary.
        assert chain.credential_hash(b'cred') == NullVerifier().credential_hash(b'cred')


class TestMfaCredentialEnvelope:
    def test_pack_unpack_roundtrip(self):
        c = MfaCredential([b'piv-envelope', b'123456'])
        assert MfaCredential.unpack(c.pack()).blobs == [b'piv-envelope', b'123456']

    def test_bare_cert_not_mistaken_for_composite(self):
        # A DER cert begins 0x30 0x82..., never the MFA1 magic.
        assert MfaCredential.unpack(b'\x30\x82\x01\x00rest') is None
        assert MfaCredential.unpack(b'') is None
        assert MfaCredential.unpack(b'MFA') is None  # too short

    def test_trailing_bytes_rejected(self):
        assert MfaCredential.unpack(MfaCredential([b'a']).pack() + b'x') is None


class TestMfaChainComposite:
    def test_composite_dispatches_blob_per_factor(self):
        primary = _FixedVerifier(ZtaStatus.VERIFIED, cred_hash=_PRIMARY)
        second = _FixedVerifier(ZtaStatus.VERIFIED, cred_hash=_SECOND, secondary=True)
        chain = MfaChain([primary, second])
        cred = MfaCredential([b'piv-blob', b'totp-code']).pack()
        r = chain.verify_credential(cred)
        assert r.status is ZtaStatus.VERIFIED
        assert r.credential_hash == _PRIMARY          # primary's hash
        assert primary.seen == [b'piv-blob']          # each got its own blob
        assert second.seen == [b'totp-code']

    def test_composite_invalid_second_factor_rejected(self):
        primary = _FixedVerifier(ZtaStatus.VERIFIED, cred_hash=_PRIMARY)
        second = _FixedVerifier(ZtaStatus.REJECTED, secondary=True)
        chain = MfaChain([primary, second])
        cred = MfaCredential([b'piv-blob', b'wrong']).pack()
        assert chain.verify_credential(cred).status is ZtaStatus.REJECTED

    def test_composite_blob_count_mismatch_rejected(self):
        chain = MfaChain([_FixedVerifier(ZtaStatus.VERIFIED),
                          _FixedVerifier(ZtaStatus.VERIFIED, secondary=True)])
        # Only one blob for two factors.
        assert chain.verify_credential(
            MfaCredential([b'only-one']).pack()).status is ZtaStatus.REJECTED


class TestMfaChainBareSkipsSecondary:
    def test_bare_cred_skips_secondary_factor(self):
        # Peer admission: a bare cert runs only primary factors; the secondary
        # (TOTP) factor is not consulted and cannot block admission.
        primary = _FixedVerifier(ZtaStatus.VERIFIED, cred_hash=_PRIMARY)
        second = _FixedVerifier(ZtaStatus.REJECTED, secondary=True)
        chain = MfaChain([primary, second])
        r = chain.verify_credential(b'\x30\x82 bare cert bytes')
        assert r.status is ZtaStatus.VERIFIED       # secondary REJECTED ignored
        assert primary.seen == [b'\x30\x82 bare cert bytes']
        assert second.seen == []                    # never consulted

    def test_bare_cred_all_secondary_rejected(self):
        chain = MfaChain([_FixedVerifier(ZtaStatus.VERIFIED, secondary=True)])
        assert chain.verify_credential(b'bare').status is ZtaStatus.REJECTED
