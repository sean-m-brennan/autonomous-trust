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

    def test_each_json_carries_required_fields(self, tmp_path):
        out = tmp_path / 'out'
        corpus_to_json.convert(_CORPUS, out)
        for path in (out / 'vectors').rglob('*.json'):
            payload = json.loads(path.read_text(encoding='utf-8'))
            for key in ('case_id', 'kind', 'protocol', 'name', 'data'):
                assert key in payload, f'{path}: missing {key}'
            assert isinstance(payload['data'], dict)
