# ******************
#  Copyright 2026 Sean M. Brennan and contributors
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

"""Agreement-protocol adapter for the AT conformance corpus (Phase D).

Drives `kind: agreement_vector` cases:

  1. Build N voter Identities (deterministic seeds keyed by voter id).
  2. Construct the requested AgreementProtocol implementation
     (POA via AgreementByAuthority, POS via AgreementByStake).
  3. For each entry in `votes:`, the named voter signs an AgreementProof
     (over the blob's hash) and the harness submits it via verify().
  4. Call finalize(blob) and assert against `expected.outcome`.

Agreement has no wire-level protocol — all I/O is direct method calls
inside the AgreementProtocol instance, so this adapter never builds
queues or Messages. It does still use real PyNaCl signatures so the
voter.verify() check inside finalize matches production.
"""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any
from uuid import UUID, uuid5

from autonomous_trust.core.algorithms.agreement import AgreementProof, AgreementVoter
from autonomous_trust.core.algorithms.authority import AgreementByAuthority
from autonomous_trust.core.algorithms.stake import AgreementByStake
from autonomous_trust.core.identity import Identity
from autonomous_trust.core.identity.encrypt import Encryptor
from autonomous_trust.core.identity.sign import Signature
from autonomous_trust.core.structures.merkle import SimplestBlob

from ...common.scenario_loader import Case


_NS = UUID('00000000-0000-0000-0000-000000000aaa')


class _ScenarioBlob(SimplestBlob):
    """Minimal SimplestBlob with a stable designation derived from a payload."""

    def __init__(self, originator: UUID, uuid: UUID, payload: bytes) -> None:
        super().__init__(originator, uuid)
        self._payload = payload

    @property
    def designation(self) -> bytes:
        return (str(self.originator) + str(self.uuid)).encode('utf-8') + self._payload


class _StakeImpl(AgreementByStake):
    """Concrete AgreementByStake that reads stakes from a static map."""

    def __init__(self, me: AgreementVoter, peers: list[AgreementVoter],
                 stakes: dict[str, float]) -> None:
        super().__init__(me, peers)
        # Stakes are keyed by voter uuid (string form). 0 stake for unknown.
        self._stakes = stakes

    def _get_stake(self, voter: AgreementVoter):
        return float(self._stakes.get(str(voter.uuid), 0))

    def _pre_verify(self, blob, proof, sig) -> bool:  # noqa: ARG002
        # POS in production calls into IdentityHistory.verify_object which
        # also handles signature verification; for the harness we already
        # signed with a real Identity, so just pass through. AgreementProtocol
        # .finalize will run voter.verify(smessage) afterwards.
        return True


class _AuthorityImpl(AgreementByAuthority):
    """Concrete AgreementByAuthority for the harness (override _pre_verify only)."""

    def _pre_verify(self, blob, proof, sig) -> bool:  # noqa: ARG002
        return True


class AgreementAdapter:
    def __init__(self, corpus_root: Path) -> None:
        self.corpus_root = corpus_root

    # The four kinds Agreement is asked about; only agreement_vector is wired.

    def run_agreement_vector(self, case: Case) -> None:
        spec = case.data
        identities = self._build_voters(spec['voters'])
        myself_id = spec['myself']
        if myself_id not in identities:
            raise AssertionError(f'myself {myself_id!r} not in voters')

        myself = identities[myself_id]
        peers = [ident for pid, ident in identities.items() if pid != myself_id]

        impl_name = spec['impl']
        if impl_name == 'authority':
            threshold = spec.get('threshold_rank', 0)
            protocol = _AuthorityImpl(myself, peers, threshold_rank=threshold)
        elif impl_name == 'stake':
            stakes = self._resolve_stakes(spec.get('stakes', {}), identities)
            protocol = _StakeImpl(myself, peers, stakes)
        else:
            raise AssertionError(f'unsupported impl {impl_name!r}')

        blob = self._build_blob(spec['blob'], identities)

        for vote in spec.get('votes', []):
            voter_id = vote['by']
            if voter_id not in identities:
                raise AssertionError(f'vote.by references unknown voter {voter_id!r}')
            voter = identities[voter_id]
            proof = AgreementProof(voter.uuid, blob.get_hash(),
                                   bool(vote['approval']), nonce=None)
            signed = voter.sign(bytes(proof))
            sig_pair = (signed.message, signed.signature)
            protocol.verify(blob, proof, sig_pair)

        actual = protocol.finalize(blob)
        expected = bool(spec['expected']['outcome'])
        if actual != expected:
            raise AssertionError(
                f'finalize outcome: expected {expected}, got {actual} '
                f'(impl={impl_name}, votes={len(spec.get("votes", []))})'
            )

    # ------------------------------------------------------------------
    # Out-of-scope kinds
    # ------------------------------------------------------------------

    def run_wire_vector(self, case: Case) -> None:  # noqa: ARG002
        raise NotImplementedError(
            'agreement wire_vector handled by network adapter (AgreementProof round-trips)'
        )

    def run_crypto_vector(self, case: Case) -> None:  # noqa: ARG002
        raise NotImplementedError('agreement protocol does not own crypto vectors')

    def run_scenario(self, case: Case) -> None:
        """Walk the case's steps[] as a sequence of vote submissions.

        Differs from run_agreement_vector in two ways:
          - Single AgreementProtocol instance accumulates votes for
            multiple blobs concurrently.
          - finalize() is called per blob from expected_state.agreement,
            with each blob's outcome asserted independently.

        Does NOT use the universal scenario_engine because agreement
        protocol calls are local method invocations, not message
        exchanges. Steps carry `from: <voter>` and
        `payload: {blob, approval}`.
        """
        spec = case.data
        fixtures = spec.get('fixtures', {}) or {}
        participants = spec['participants']

        ranks = fixtures.get('ranks', {}) or {}
        impl_name = fixtures.get('impl', 'authority')
        myself_id = fixtures.get('myself')
        if myself_id is None:
            raise AssertionError("fixtures.myself is required")
        threshold = int(fixtures.get('threshold_rank', 0))

        # Build voters with deterministic seeds + ranks from the fixture.
        identities: dict[str, Identity] = {}
        for idx, spec_p in enumerate(participants):
            pid = spec_p['id']
            rank = int(ranks.get(pid, 0))
            uuid = uuid5(_NS, f'agreement:{pid}')
            sig_seed = _stretch(pid, b'sig')
            enc_seed = _stretch(pid, b'enc')
            identities[pid] = Identity(
                uuid, f'10.0.42.{idx + 1}', f'{pid}.agree', pid,
                Signature(sig_seed, public_only=False),
                Encryptor(enc_seed, public_only=False),
                'me', False, rank, 'authority',
            )

        if myself_id not in identities:
            raise AssertionError(f'myself {myself_id!r} not in participants')
        myself = identities[myself_id]
        peers = [ident for pid, ident in identities.items() if pid != myself_id]

        if impl_name == 'authority':
            protocol = _AuthorityImpl(myself, peers, threshold_rank=threshold)
        elif impl_name == 'stake':
            stakes = self._resolve_stakes(fixtures.get('stakes', {}) or {}, identities)
            protocol = _StakeImpl(myself, peers, stakes)
        else:
            raise AssertionError(f'unsupported impl {impl_name!r}')

        # Pre-build all blobs the scenario references.
        blobs_spec = fixtures.get('blobs', {}) or {}
        blobs: dict[str, _ScenarioBlob] = {}
        for blob_id, blob_spec in blobs_spec.items():
            blobs[blob_id] = self._build_scenario_blob(
                blob_id, blob_spec, identities,
            )

        # Apply each vote step.
        for step in spec['steps']:
            fn = step.get('function')
            payload = step.get('payload') or {}
            blob_id = payload.get('blob')
            if blob_id not in blobs:
                raise AssertionError(
                    f'step {step["id"]}: references unknown blob {blob_id!r}'
                )
            blob = blobs[blob_id]

            if fn == 'finalize':
                # Inline finalize step. Lets a scenario assert outcomes
                # mid-trace (e.g. late-vote-after-finalize), not just at
                # the end via expected_state.
                if 'expected_outcome' not in payload:
                    raise AssertionError(
                        f'step {step["id"]}: finalize step must declare '
                        f'payload.expected_outcome'
                    )
                expected_outcome = bool(payload['expected_outcome'])
                actual = protocol.finalize(blob)
                if actual != expected_outcome:
                    raise AssertionError(
                        f'step {step["id"]}: finalize({blob_id}) '
                        f'expected {expected_outcome}, got {actual}'
                    )
                continue

            if fn != 'vote':
                raise AssertionError(
                    f'step {step["id"]}: agreement scenarios only support '
                    f'function=vote|finalize (got {fn!r})'
                )

            voter_id = step['from']
            if voter_id not in identities:
                raise AssertionError(
                    f'step {step["id"]}: vote from unknown voter {voter_id!r}'
                )
            voter = identities[voter_id]
            proof = AgreementProof(voter.uuid, blob.get_hash(),
                                   bool(payload.get('approval', False)),
                                   nonce=None)
            signed = voter.sign(bytes(proof))
            sig_pair = (signed.message, signed.signature)
            protocol.verify(blob, proof, sig_pair)

        # Drive finalize per blob and assert against expected_state.
        agreement_expected = spec.get('expected_state', {}).get('agreement', {}) or {}
        for blob_id, blob_expected in agreement_expected.items():
            if blob_id not in blobs:
                raise AssertionError(
                    f'expected_state references unknown blob {blob_id!r}'
                )
            outcome = bool(blob_expected.get('outcome', False))
            actual = protocol.finalize(blobs[blob_id])
            if actual != outcome:
                raise AssertionError(
                    f'finalize({blob_id}) expected {outcome}, got {actual}'
                )

    def _build_scenario_blob(self, blob_id: str, spec: dict[str, Any],
                             identities: dict[str, Identity]) -> _ScenarioBlob:
        originator_id = spec['originator']
        if originator_id not in identities:
            raise AssertionError(
                f'blob {blob_id!r}: originator {originator_id!r} not a voter'
            )
        originator_uuid = identities[originator_id].uuid
        blob_uuid = uuid5(_NS, f'blob:{blob_id}')
        payload = spec.get('payload', blob_id).encode('utf-8')
        return _ScenarioBlob(originator_uuid, blob_uuid, payload)

    def run_negative(self, case: Case) -> None:
        from ...common.negative_runner import run_wire_negative
        expected = case.data['expected']['reason_class']
        observed = run_wire_negative(self.corpus_root, case)
        if observed != expected:
            raise AssertionError(
                f'reason_class mismatch: expected {expected!r}, '
                f'observed {observed!r}'
            )

    # ------------------------------------------------------------------
    # Builders
    # ------------------------------------------------------------------

    def _build_voters(self, specs: list[dict[str, Any]]) -> dict[str, Identity]:
        identities: dict[str, Identity] = {}
        for idx, spec in enumerate(specs):
            pid = spec['id']
            rank = int(spec.get('rank', 0))
            uuid = UUID(spec['uuid']) if 'uuid' in spec else uuid5(_NS, f'agreement:{pid}')
            sig_seed = _stretch(pid, b'sig')
            enc_seed = _stretch(pid, b'enc')
            identity = Identity(
                uuid, f'10.0.42.{idx + 1}', f'{pid}.agree', pid,
                Signature(sig_seed, public_only=False),
                Encryptor(enc_seed, public_only=False),
                'me', False, rank, 'authority',
            )
            identities[pid] = identity
        return identities

    def _resolve_stakes(self, raw: dict[str, Any],
                        identities: dict[str, Identity]) -> dict[str, float]:
        # Schema keys stakes by voter id; AgreementByStake._get_stake is
        # called with an AgreementVoter (Identity) whose .uuid we look up.
        out: dict[str, float] = {}
        for pid, stake in raw.items():
            if pid not in identities:
                raise AssertionError(f'stakes references unknown voter {pid!r}')
            out[str(identities[pid].uuid)] = float(stake)
        return out

    def _build_blob(self, spec: dict[str, Any],
                    identities: dict[str, Identity]) -> _ScenarioBlob:
        originator_id = spec['originator']
        if originator_id not in identities:
            raise AssertionError(f'blob.originator references unknown voter {originator_id!r}')
        originator_uuid = identities[originator_id].uuid
        blob_uuid = uuid5(_NS, f'blob:{spec["uuid"]}')
        payload = spec.get('payload', spec['uuid']).encode('utf-8')
        return _ScenarioBlob(originator_uuid, blob_uuid, payload)


def _stretch(pid: str, role: bytes) -> bytes:
    return hashlib.sha256(b'at-conformance:' + role + b':' + pid.encode('utf-8')).hexdigest().encode('ascii')
