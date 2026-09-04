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
"""Conformance adapter for certificate-carrying interfaces (R+D.md §12.3).

A ``certificate`` scenario declares a model in ``fixtures.certificates`` --
the same shape a ``certificates.json`` file carries -- and a list of
``fixtures.claims``, each ``{capability, kwargs, result, certificate}``. Every
row is fed through this runtime's verifier and the verdict, plus the score it
maps to, is asserted per row.

The verdict is asserted alongside the score because three of the five produce
no score at all and would be indistinguishable from each other on the numbers:
``absent`` is a fact about the peer, ``indeterminate`` is our own record
failing and must never reach a score, and ``none`` is a capability nobody
declared or one declared uncertifiable. A runtime that collapsed any two of
those would look identical if only the scores were pinned.

``fixtures.seed`` is the verifier's challenge for the one probabilistic
checker. In production it comes from the requestor's own entropy at check time
and is unpredictable to the peer; here it is fixed so the replay reproduces the
verdicts, which is the whole reason it is a parameter rather than a draw.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from autonomous_trust.core.certificates import (ABSENT_SCORE, INVALID_SCORE,
                                                VALID_SCORE,
                                                CertificateVerifier,
                                                parse_certificates)

from ...common.scenario_loader import Case

#: verdict -> the score it carries, or None for the ones that produce none.
_SCORES = {
    'valid': VALID_SCORE,
    'invalid': INVALID_SCORE,
    'absent': ABSENT_SCORE,
    'indeterminate': None,
    'none': None,
}


class CertificateAdapter:
    def __init__(self, corpus_root: Path) -> None:
        self.corpus_root = corpus_root

    # -- kinds this adapter does not handle ---------------------------------
    def run_wire_vector(self, case: Case) -> None:  # noqa: ARG002
        raise NotImplementedError('certificate adapter handles kind:scenario only')

    def run_crypto_vector(self, case: Case) -> None:  # noqa: ARG002
        raise NotImplementedError('certificate adapter handles kind:scenario only')

    def run_agreement_vector(self, case: Case) -> None:  # noqa: ARG002
        raise NotImplementedError('certificate adapter handles kind:scenario only')

    def run_negative(self, case: Case) -> None:  # noqa: ARG002
        raise NotImplementedError('certificate adapter handles kind:scenario only')

    # -- the certificate scenario -------------------------------------------
    def run_scenario(self, case: Case) -> None:
        spec = case.data
        fixtures = spec.get('fixtures') or {}
        declaration = fixtures.get('certificates')
        if declaration is None:
            raise AssertionError(
                'certificate scenario needs fixtures.certificates')
        rows = fixtures.get('claims') or []
        seed = int(fixtures.get('seed', 0))

        participants = spec.get('participants') or []
        host = next((p for p in participants if p.get('role') == 'new_node'),
                    participants[0] if participants else None)
        if host is None:
            raise AssertionError('certificate scenario needs a participant')

        verifier = CertificateVerifier(parse_certificates(declaration))
        verdicts: list[str] = []
        scores: list[Any] = []
        for row in rows:
            verdict, _reason = verifier.evaluate(
                row.get('capability'), row.get('result'),
                row.get('certificate'), row.get('kwargs') or {}, seed)
            verdicts.append(verdict)
            # Taken from the verifier itself rather than from the table above,
            # so a runtime that mapped a verdict to the wrong number is caught
            # here and not only in the C twin.
            paired = verifier.verify(
                row.get('capability'), row.get('result'),
                row.get('certificate'), row.get('kwargs') or {}, seed)
            scores.append(None if paired is None else paired[0])

        expected = (spec.get('expected_state') or {}).get(host['id'], {})
        self._assert(host['id'], rows, 'claim_verdicts', expected, verdicts,
                     lambda got, want: got == want)
        self._assert(host['id'], rows, 'claim_scores', expected, scores,
                     lambda got, want: (got is None and want is None)
                     or (got is not None and want is not None
                         and abs(float(got) - float(want)) < 1e-9))
        # Cross-check the mapping the scenario spells against the one the
        # verifier applies: pinning both independently is what catches a
        # runtime that got the verdict right and the score wrong.
        for i, verdict in enumerate(verdicts):
            assert scores[i] == _SCORES[verdict], (
                f"{host['id']}: row {i} reported verdict {verdict!r} but "
                f'scored {scores[i]!r}')

    @staticmethod
    def _assert(host_id, rows, key, expected, got, eq) -> None:
        if key not in expected:
            return
        want = list(expected[key])
        assert len(want) == len(got), (
            f'{host_id}: {len(got)} claims checked, {len(want)} {key} pinned')
        for i, (g, w) in enumerate(zip(got, want)):
            assert eq(g, w), (
                f'{host_id}: row {i} ({rows[i].get("capability")}) reported '
                f'{key[:-1]} {g!r}, expected {w!r}')
