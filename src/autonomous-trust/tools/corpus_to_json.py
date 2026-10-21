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

"""corpus_to_json: precompile the YAML conformance corpus to JSON for non-Python harnesses.

Walks `scenarios/` and `vectors/` under <in>, parses each YAML through the
shared loader (which validates against the JSON Schemas), and writes JSON
mirrors under <out> with the same relative path layout. Resolved fixtures
are baked in so the C harness doesn't need to re-implement `<ref:...>`
substitution.

Idempotent: outputs are byte-stable for unchanged inputs. A mirror whose YAML
source is gone (a scenario moved to another protocol, or deleted) is deleted
too, so a reused output directory cannot index a case twice.

Used by `src/c/conformance/CMakeLists.txt` as a build-time custom command;
the C harness reads only JSON via jansson.
"""

from __future__ import annotations

import argparse
import json
import shutil
import sys
from pathlib import Path

from conformance.harness.common.scenario_loader import (
    _load_schemas,
    load_case,
)


def _to_json_serializable(obj: object) -> object:
    """Coerce ruamel-yaml types (CommentedMap/Seq, etc.) to plain dict/list."""
    if isinstance(obj, dict):
        return {str(k): _to_json_serializable(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_to_json_serializable(v) for v in obj]
    return obj


class CorpusMergeError(ValueError):
    """Two corpus roots contribute the same mirror path or case id."""


def convert(corpus_root: Path, out_dir: Path,
            extra_roots: tuple = ()) -> int:
    """Walk the corpus, write JSON mirrors. Returns case count.

    ``extra_roots`` are further corpus roots (an extension's own protocol,
    doc/architecture/extensions.md "External extensions"): their
    ``scenarios/``, ``vectors/`` and ``testdata/`` merge into the same mirror
    and index, validated against ``corpus_root``'s schemas. A mirror path or
    case id two roots both contribute is refused, never silently overwritten."""
    corpus_root = corpus_root.resolve()
    out_dir = out_dir.resolve()
    roots = [corpus_root] + [Path(r).resolve() for r in extra_roots]

    schemas = _load_schemas(corpus_root / 'schema')

    count = 0
    written: set[Path] = set()
    case_ids: dict[str, Path] = {}
    for croot in roots:
        for sub in ('scenarios', 'vectors'):
            root = croot / sub
            if not root.is_dir():
                continue
            for path in sorted(root.rglob('*.yaml')):
                if path.name.startswith(('.', '_')):
                    continue
                case = load_case(path, schemas)
                rel = path.relative_to(croot).with_suffix('.json')
                target = out_dir / rel
                if target in written:
                    raise CorpusMergeError(f'{rel}: contributed by two corpus roots')
                if case.case_id in case_ids:
                    raise CorpusMergeError(f'{case.case_id}: in {case_ids[case.case_id]} '
                                           f'and {path}')
                case_ids[case.case_id] = path
                target.parent.mkdir(parents=True, exist_ok=True)
                payload = {
                    'case_id': case.case_id,
                    'kind': case.kind,
                    'protocol': case.protocol,
                    'name': case.name,
                    'source_path': str(path.relative_to(croot)),
                    'data': _to_json_serializable(case.data),
                }
                target.write_text(
                    json.dumps(payload, indent=2, sort_keys=True) + '\n',
                    encoding='utf-8',
                )
                written.add(target)
                count += 1

    # Drop mirrors with no YAML source left in any root (a scenario moved or
    # deleted): the index below lists every JSON under the tree, so a stale
    # copy would run as a second case.
    for sub in ('scenarios', 'vectors'):
        root = out_dir / sub
        if not root.is_dir():
            continue
        for stale in sorted(root.rglob('*.json')):
            if stale not in written:
                stale.unlink()
        for d in sorted((p for p in root.rglob('*') if p.is_dir()),
                        key=lambda p: len(p.parts), reverse=True):
            if not any(d.iterdir()):
                d.rmdir()

    # Mirror the testdata/ tree verbatim so the C harness can resolve
    # paths like `expected.json_wire: testdata/wire/foo/expected.json`
    # relative to its own corpus root, without needing to know where the
    # original YAML lives.
    # Every root's testdata merges into the one tree (the C runner has a
    # single testdata root); a file two roots both supply is refused.
    testdata_dst = out_dir / 'testdata'
    if testdata_dst.exists():
        shutil.rmtree(testdata_dst)
    for croot in roots:
        testdata_src = croot / 'testdata'
        if not testdata_src.is_dir():
            continue
        for f in testdata_src.rglob('*'):
            if f.is_file() and (testdata_dst / f.relative_to(testdata_src)).exists():
                raise CorpusMergeError(f'testdata/{f.relative_to(testdata_src)}: '
                                       f'contributed by two corpus roots')
        shutil.copytree(testdata_src, testdata_dst, dirs_exist_ok=True)

    # Top-level index so the C runner can discover cases without a
    # filesystem walk. Order matches Python loader's stable alphabetical.
    index = []
    for sub in ('scenarios', 'vectors'):
        root = out_dir / sub
        if root.is_dir():
            for p in sorted(root.rglob('*.json')):
                index.append(str(p.relative_to(out_dir)))
    (out_dir / 'index.json').write_text(
        json.dumps(index, indent=2) + '\n', encoding='utf-8'
    )
    return count


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog='corpus_to_json')
    parser.add_argument('--in', dest='in_dirs', required=True, action='append',
                        help='Path to a conformance corpus root. The first holds '
                             'schema/; repeat for extensions\' corpora.')
    parser.add_argument('--out', dest='out_dir', required=True,
                        help='Output directory for JSON mirrors.')
    args = parser.parse_args(argv)

    in_dir = Path(args.in_dirs[0])
    out_dir = Path(args.out_dir)
    if not (in_dir / 'schema').is_dir():
        print(f'corpus_to_json: --in {in_dir} does not look like a corpus root '
              f'(no schema/ subdir)', file=sys.stderr)
        return 2
    try:
        n = convert(in_dir, out_dir, tuple(args.in_dirs[1:]))
    except CorpusMergeError as err:
        print(f'corpus_to_json: {err}', file=sys.stderr)
        return 2
    print(f'corpus_to_json: wrote {n} cases to {out_dir}')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
