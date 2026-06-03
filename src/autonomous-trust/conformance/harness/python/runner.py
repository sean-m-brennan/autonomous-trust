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

"""Python harness for the AT conformance corpus.

Owns dispatch from `Case` -> per-protocol adapter, collects `CaseResult`
records, and emits a result JSON in the corpus's `results/` directory.
"""

from __future__ import annotations

import json
import subprocess
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ..common.scenario_loader import Case, discover

from .adapters.agreement import AgreementAdapter
from .adapters.bootstrap import BootstrapAdapter
from .adapters.identity import IdentityAdapter
from .adapters.negotiation import NegotiationAdapter
from .adapters.network import NetworkAdapter
from .adapters.reputation import ReputationAdapter


CORPUS_ROOT = Path(__file__).resolve().parents[2]


@dataclass
class CaseResult:
    case_id: str
    status: str  # pass | fail | skip
    duration_ms: int = 0
    reason_class: str | None = None
    rejected_at_step: int | None = None
    detail: str | None = None

    def to_dict(self) -> dict[str, Any]:
        d = {k: v for k, v in asdict(self).items() if v is not None}
        return d


@dataclass
class Report:
    implementation: str = 'python'
    implementation_version: str = field(default_factory=lambda: _git_sha())
    schema_version: str = '1'
    started_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    cases: list[CaseResult] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            'implementation': self.implementation,
            'implementation_version': self.implementation_version,
            'schema_version': self.schema_version,
            'started_at': self.started_at,
            'cases': [c.to_dict() for c in self.cases],
        }


def _git_sha() -> str:
    try:
        out = subprocess.check_output(
            ['git', 'rev-parse', '--short=12', 'HEAD'],
            cwd=str(CORPUS_ROOT),
            stderr=subprocess.DEVNULL,
        )
        return out.decode('ascii').strip()
    except (subprocess.CalledProcessError, FileNotFoundError):
        return 'unknown'


# Adapter registry. The protocol field of a case picks the adapter; each
# adapter handles every kind it knows about (raising NotImplementedError
# for kinds it does not yet support).
def _adapters() -> dict[str, Any]:
    return {
        'network': NetworkAdapter(corpus_root=CORPUS_ROOT),
        'identity': IdentityAdapter(corpus_root=CORPUS_ROOT),
        'agreement': AgreementAdapter(corpus_root=CORPUS_ROOT),
        'negotiation': NegotiationAdapter(corpus_root=CORPUS_ROOT),
        'reputation': ReputationAdapter(corpus_root=CORPUS_ROOT),
        'bootstrap': BootstrapAdapter(corpus_root=CORPUS_ROOT),
    }


def run_case(case: Case, adapters: dict[str, Any]) -> CaseResult:
    adapter = adapters.get(case.protocol)
    if adapter is None:
        return CaseResult(case_id=case.case_id, status='skip',
                          detail=f'no adapter for protocol {case.protocol!r}')
    method = {
        'wire_vector': 'run_wire_vector',
        'crypto_vector': 'run_crypto_vector',
        'scenario': 'run_scenario',
        'negative': 'run_negative',
        'agreement_vector': 'run_agreement_vector',
    }.get(case.kind)
    if method is None or not hasattr(adapter, method):
        return CaseResult(case_id=case.case_id, status='skip',
                          detail=f'adapter {type(adapter).__name__} does not handle kind {case.kind!r}')
    t0 = time.monotonic()
    try:
        getattr(adapter, method)(case)
        ms = int((time.monotonic() - t0) * 1000)
        return CaseResult(case_id=case.case_id, status='pass', duration_ms=ms)
    except NotImplementedError as exc:
        return CaseResult(case_id=case.case_id, status='skip', detail=str(exc))
    except AssertionError as exc:
        ms = int((time.monotonic() - t0) * 1000)
        return CaseResult(case_id=case.case_id, status='fail',
                          duration_ms=ms, detail=str(exc) or 'assertion failed')
    except Exception as exc:  # noqa: BLE001 — runner needs broad capture
        ms = int((time.monotonic() - t0) * 1000)
        return CaseResult(case_id=case.case_id, status='fail',
                          duration_ms=ms, reason_class=type(exc).__name__,
                          detail=f'{type(exc).__name__}: {exc}')


def run_all() -> Report:
    """Discover and execute every case under CORPUS_ROOT. Returns the report."""
    cases = discover(CORPUS_ROOT)
    adapters = _adapters()
    report = Report()
    for case in cases:
        report.cases.append(run_case(case, adapters))
    return report


def write_report(report: Report) -> Path:
    out_dir = CORPUS_ROOT / 'results'
    out_dir.mkdir(parents=True, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    out_path = out_dir / f'python-{ts}.json'
    out_path.write_text(json.dumps(report.to_dict(), indent=2) + '\n', encoding='utf-8')
    return out_path


if __name__ == '__main__':
    report = run_all()
    out = write_report(report)
    failed = [c for c in report.cases if c.status == 'fail']
    print(f'wrote {out}: {len(report.cases)} cases, {len(failed)} failed')
    for c in failed:
        print(f'  FAIL {c.case_id}: {c.detail}')
    raise SystemExit(1 if failed else 0)
