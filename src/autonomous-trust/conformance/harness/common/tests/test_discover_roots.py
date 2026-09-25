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
"""scenario_loader.discover over several corpus roots (conformance plug-ins,
doc/architecture/extensions.md "External extensions")."""
from pathlib import Path

import pytest

from ..scenario_loader import CorpusLoadError, discover

_CORPUS = Path(__file__).resolve().parents[3]
_SRC = _CORPUS / 'scenarios' / 'identity' / 'amnesia-readmission.yaml'


def _plugin(tmp_path, name, rename=True):
    root = tmp_path / name
    (root / 'scenarios' / 'identity').mkdir(parents=True)
    text = _SRC.read_text(encoding='utf-8')
    if rename:
        text = text.replace('name: amnesia-readmission', f'name: amnesia-readmission-{name}', 1)
    (root / 'scenarios' / 'identity' / f'{name}.yaml').write_text(text, encoding='utf-8')
    return root


def test_a_plugin_root_adds_its_cases_after_ats():
    base = discover(_CORPUS)
    assert base


def test_extra_roots_are_appended(tmp_path):
    base = discover(_CORPUS)
    cases = discover(_CORPUS, [_plugin(tmp_path, 'p')])
    assert len(cases) == len(base) + 1
    assert cases[-1].name == 'amnesia-readmission-p'
    assert [c.case_id for c in cases[:len(base)]] == [c.case_id for c in base]


def test_a_case_id_two_roots_share_is_refused(tmp_path):
    # Byte-identical to AT's own file: same protocol, name and digest.
    with pytest.raises(CorpusLoadError, match='amnesia-readmission'):
        discover(_CORPUS, [_plugin(tmp_path, 'dup', rename=False)])
