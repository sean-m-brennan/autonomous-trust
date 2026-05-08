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

"""pytest entry for the AT conformance corpus.

Each parametrized case produces one pytest test. The runner also writes a
combined results/python-<ts>.json after the session for cross-language diffing.
"""

from __future__ import annotations

import pytest

from ..common.scenario_loader import Case, discover
from .runner import (
    CORPUS_ROOT,
    Report,
    _adapters,
    run_case,
    write_report,
)


_CASES: list[Case] = discover(CORPUS_ROOT)
_ADAPTERS = _adapters()
_REPORT = Report()


@pytest.mark.parametrize(
    'case',
    _CASES,
    ids=[c.case_id for c in _CASES],
)
def test_corpus_case(case: Case) -> None:
    result = run_case(case, _ADAPTERS)
    _REPORT.cases.append(result)
    if result.status == 'skip':
        pytest.skip(result.detail or 'skipped')
    if result.status == 'fail':
        pytest.fail(result.detail or 'case failed')


def teardown_module(_module: object) -> None:
    if _REPORT.cases:
        write_report(_REPORT)
