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

import json
import shutil
from pathlib import Path

import pytest

from .. import corpus_to_json


_REPO = Path(__file__).resolve().parents[2]
_CORPUS = _REPO / 'conformance'


class TestCorpusToJson:
    def test_writes_index_and_one_file_per_case(self, tmp_path):
        out = tmp_path / 'out'
        n = corpus_to_json.convert(_CORPUS, out)
        assert n > 0
        assert (out / 'index.json').is_file()
        index = json.loads((out / 'index.json').read_text(encoding='utf-8'))
        # Index entry count matches conversion count.
        assert len(index) == n
        # Each indexed file exists.
        for rel in index:
            assert (out / rel).is_file()

    def test_output_is_byte_stable(self, tmp_path):
        out_a = tmp_path / 'a'
        out_b = tmp_path / 'b'
        corpus_to_json.convert(_CORPUS, out_a)
        corpus_to_json.convert(_CORPUS, out_b)
        index_a = (out_a / 'index.json').read_text(encoding='utf-8')
        index_b = (out_b / 'index.json').read_text(encoding='utf-8')
        assert index_a == index_b
        # Spot-check a couple of files.
        for sub in ('vectors/crypto/ed25519-rfc8032-test1.json',
                    'scenarios/identity/amnesia-readmission.json'):
            a = (out_a / sub).read_text(encoding='utf-8')
            b = (out_b / sub).read_text(encoding='utf-8')
            assert a == b, sub

    @staticmethod
    def _extra_root(tmp_path, name='plugin', scenario='amnesia-readmission'):
        """A second corpus root holding a copy of one AT scenario under a new
        protocol directory and name, as an extension's plug-in would."""
        root = tmp_path / name
        (root / 'scenarios' / 'identity').mkdir(parents=True)
        src = (_CORPUS / 'scenarios' / 'identity' / f'{scenario}.yaml').read_text(encoding='utf-8')
        src = src.replace(f'name: {scenario}', f'name: {scenario}-{name}', 1)
        (root / 'scenarios' / 'identity' / f'{scenario}-{name}.yaml').write_text(src, encoding='utf-8')
        return root

    def test_a_mirror_without_a_source_is_deleted(self, tmp_path):
        """A scenario that moved or left (an extension's plug-in no longer
        passed) must not leave its old JSON behind in a reused build dir,
        where the index would list it and the C harness run it twice."""
        out = tmp_path / 'out'
        extra = self._extra_root(tmp_path)
        corpus_to_json.convert(_CORPUS, out, (extra,))
        moved = out / 'scenarios' / 'identity' / 'amnesia-readmission-plugin.json'
        assert moved.is_file()
        gone_dir = out / 'scenarios' / 'retired'
        gone_dir.mkdir()
        (gone_dir / 'x.json').write_text('{}', encoding='utf-8')
        corpus_to_json.convert(_CORPUS, out)          # plug-in not passed
        assert not moved.exists()
        assert not gone_dir.exists()
        index = json.loads((out / 'index.json').read_text(encoding='utf-8'))
        assert 'scenarios/identity/amnesia-readmission-plugin.json' not in index
        assert 'scenarios/identity/amnesia-readmission.json' in index

    def test_extra_roots_merge_into_one_index(self, tmp_path):
        out = tmp_path / 'out'
        n_core = corpus_to_json.convert(_CORPUS, tmp_path / 'core')
        n = corpus_to_json.convert(_CORPUS, out, (self._extra_root(tmp_path),))
        assert n == n_core + 1
        index = json.loads((out / 'index.json').read_text(encoding='utf-8'))
        assert len(index) == n
        payload = json.loads((out / 'scenarios' / 'identity' /
                              'amnesia-readmission-plugin.json').read_text(encoding='utf-8'))
        assert payload['source_path'] == 'scenarios/identity/amnesia-readmission-plugin.yaml'

    def test_two_roots_supplying_one_case_are_refused(self, tmp_path):
        a = self._extra_root(tmp_path, 'a')
        b = tmp_path / 'b'
        (b / 'scenarios' / 'identity').mkdir(parents=True)
        f = a / 'scenarios' / 'identity' / 'amnesia-readmission-a.yaml'
        (b / 'scenarios' / 'identity' / f.name).write_bytes(f.read_bytes())
        with pytest.raises(corpus_to_json.CorpusMergeError):
            corpus_to_json.convert(_CORPUS, tmp_path / 'out', (a, b))

    def test_each_json_carries_required_fields(self, tmp_path):
        out = tmp_path / 'out'
        corpus_to_json.convert(_CORPUS, out)
        for path in (out / 'vectors').rglob('*.json'):
            payload = json.loads(path.read_text(encoding='utf-8'))
            for key in ('case_id', 'kind', 'protocol', 'name', 'data'):
                assert key in payload, f'{path}: missing {key}'
            assert isinstance(payload['data'], dict)
