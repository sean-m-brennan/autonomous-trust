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

"""Python harness for the AT conformance corpus.

Owns dispatch from `Case` -> per-protocol adapter, collects `CaseResult`
records, and emits a result JSON in the corpus's `results/` directory.
"""

from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ..common.scenario_loader import Case, discover

from .adapters.agreement import AgreementAdapter
from .adapters.bootstrap import BootstrapAdapter
from .adapters.physics import PhysicsAdapter
from .adapters.calibration import CalibrationAdapter
from .adapters.prequential import PrequentialAdapter
from .adapters.certificate import CertificateAdapter
try:
    # First contact is an extension (FEATURE_SPLIT_PLAN Phase 7): without it,
    # its contacts protocol has no adapter and skips, as C's does without
    # libat_first_contact.
    from .adapters.contacts import ContactsAdapter
except ImportError:
    ContactsAdapter = None
try:
    # DTN is an extension (FEATURE_SPLIT_PLAN Phase 9): without it, its dtn
    # protocol has no adapter and skips, as C's does without libat_dtn.
    from .adapters.dtn import DtnAdapter
except ImportError:
    DtnAdapter = None
from .adapters.replication import ReplicationAdapter
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
        'physics': PhysicsAdapter(corpus_root=CORPUS_ROOT),
        'certificate': CertificateAdapter(corpus_root=CORPUS_ROOT),
        'calibration': CalibrationAdapter(corpus_root=CORPUS_ROOT),
        'prequential': PrequentialAdapter(corpus_root=CORPUS_ROOT),
        'replication': ReplicationAdapter(corpus_root=CORPUS_ROOT),
        **({'contacts': ContactsAdapter(corpus_root=CORPUS_ROOT)}
           if ContactsAdapter is not None else {}),
        **({'dtn': DtnAdapter(corpus_root=CORPUS_ROOT)}
           if DtnAdapter is not None else {}),
        **_plugin_adapters(),
    }


#: A conformance plug-in contributes its own protocol from outside this tree
#: (doc/architecture/extensions.md, "External extensions"): a directory holding
#: `scenarios/<protocol>/*.yaml` and a `conformance_plugin.py` that sets
#: ``SYS_PATH`` (directories to prepend, e.g. its Python distribution) and
#: defines ``adapters()`` -> {protocol: adapter class}. Listed, os.pathsep-
#: separated, in this variable. Without a plug-in its protocol is simply not in
#: the corpus.
PLUGINS_ENV = 'AT_CONFORMANCE_PLUGINS'
PLUGIN_MODULE = 'conformance_plugin.py'


def plugin_roots() -> list[Path]:
    """The plug-in corpus roots named by $AT_CONFORMANCE_PLUGINS."""
    return [Path(p).resolve() for p in os.environ.get(PLUGINS_ENV, '').split(os.pathsep)
            if p.strip()]


def _load_plugin(root: Path):
    path = root / PLUGIN_MODULE
    if not path.is_file():
        raise RuntimeError(f'{PLUGINS_ENV}: no {PLUGIN_MODULE} in {root}')
    name = f'_at_conformance_plugin_{abs(hash(str(root)))}'
    module = sys.modules.get(name)
    if module is None:
        spec = importlib.util.spec_from_file_location(name, path)
        module = importlib.util.module_from_spec(spec)
        sys.modules[name] = module
        spec.loader.exec_module(module)
        for entry in reversed(getattr(module, 'SYS_PATH', ())):
            entry = str((root / entry).resolve())
            if entry not in sys.path:
                sys.path.insert(0, entry)
    return module


def _plugin_adapters() -> dict[str, Any]:
    found: dict[str, Any] = {}
    for root in plugin_roots():
        for protocol, cls in _load_plugin(root).adapters().items():
            if protocol in found:
                raise RuntimeError(f'{PLUGINS_ENV}: two plug-ins own protocol {protocol!r}')
            found[protocol] = cls(corpus_root=root)
    return found


def discover_all() -> list[Case]:
    """AT's corpus and every plug-in's, as one list."""
    return discover(CORPUS_ROOT, plugin_roots())


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
    cases = discover_all()
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
