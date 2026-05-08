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

from .. import diff_results


def _report(impl: str, cases: list[dict]) -> dict:
    return {
        'implementation': impl,
        'schema_version': '1',
        'started_at': '2026-05-08T00:00:00Z',
        'cases': cases,
    }


class TestDiff:
    def test_clean_when_both_pass(self):
        lhs = _report('python', [{'case_id': 'a', 'status': 'pass'}])
        rhs = _report('c', [{'case_id': 'a', 'status': 'pass'}])
        d = diff_results.diff(lhs, rhs)
        assert d.is_clean
        assert d.asymmetric_pass_fail == []

    def test_pass_vs_fail_is_asymmetric(self):
        lhs = _report('python', [{'case_id': 'a', 'status': 'pass'}])
        rhs = _report('c', [{'case_id': 'a', 'status': 'fail'}])
        d = diff_results.diff(lhs, rhs)
        assert not d.is_clean
        assert d.asymmetric_pass_fail == [('a', 'pass', 'fail')]

    def test_skip_on_either_side_is_not_asymmetric(self):
        lhs = _report('python', [{'case_id': 'a', 'status': 'pass'}])
        rhs = _report('c', [{'case_id': 'a', 'status': 'skip'}])
        d = diff_results.diff(lhs, rhs)
        assert d.is_clean

    def test_only_one_side_present(self):
        lhs = _report('python', [{'case_id': 'a', 'status': 'pass'}])
        rhs = _report('c', [{'case_id': 'b', 'status': 'pass'}])
        d = diff_results.diff(lhs, rhs)
        assert d.only_lhs == ['a']
        assert d.only_rhs == ['b']
        # is_clean ignores coverage gaps unless --strict-coverage was used.
        assert d.is_clean

    def test_main_returns_zero_on_skip_mismatch(self, tmp_path):
        import json
        py = tmp_path / 'py.json'
        c = tmp_path / 'c.json'
        py.write_text(json.dumps(_report('python', [{'case_id': 'a', 'status': 'pass'}])))
        c.write_text(json.dumps(_report('c', [{'case_id': 'a', 'status': 'skip'}])))
        rc = diff_results.main([str(py), str(c)])
        assert rc == 0

    def test_main_returns_one_on_real_asymmetry(self, tmp_path):
        import json
        py = tmp_path / 'py.json'
        c = tmp_path / 'c.json'
        py.write_text(json.dumps(_report('python', [{'case_id': 'a', 'status': 'pass'}])))
        c.write_text(json.dumps(_report('c', [{'case_id': 'a', 'status': 'fail'}])))
        rc = diff_results.main([str(py), str(c)])
        assert rc == 1

    def test_strict_coverage_flags_one_sided(self, tmp_path):
        import json
        py = tmp_path / 'py.json'
        c = tmp_path / 'c.json'
        py.write_text(json.dumps(_report('python', [{'case_id': 'a', 'status': 'pass'}])))
        c.write_text(json.dumps(_report('c', [])))
        # Without strict, returns 0.
        assert diff_results.main([str(py), str(c)]) == 0
        # With strict, returns 1.
        assert diff_results.main([str(py), str(c), '--strict-coverage']) == 1
