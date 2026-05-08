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

"""corpus_to_json: precompile the YAML conformance corpus to JSON for non-Python harnesses.

Walks `scenarios/` and `vectors/` under <in>, parses each YAML through the
shared loader (which validates against the JSON Schemas), and writes JSON
mirrors under <out> with the same relative path layout. Resolved fixtures
are baked in so the C harness doesn't need to re-implement `<ref:...>`
substitution.

Idempotent: outputs are byte-stable for unchanged inputs.

Used by `src/c/conformance/CMakeLists.txt` as a build-time custom command;
the C harness reads only JSON via jansson.
"""

from __future__ import annotations

import argparse
import json
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


def convert(corpus_root: Path, out_dir: Path) -> int:
    """Walk the corpus, write JSON mirrors. Returns case count."""
    corpus_root = corpus_root.resolve()
    out_dir = out_dir.resolve()

    schemas = _load_schemas(corpus_root / 'schema')

    count = 0
    for sub in ('scenarios', 'vectors'):
        root = corpus_root / sub
        if not root.is_dir():
            continue
        for path in sorted(root.rglob('*.yaml')):
            if path.name.startswith(('.', '_')):
                continue
            case = load_case(path, schemas)
            rel = path.relative_to(corpus_root).with_suffix('.json')
            target = out_dir / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            payload = {
                'case_id': case.case_id,
                'kind': case.kind,
                'protocol': case.protocol,
                'name': case.name,
                'source_path': str(path.relative_to(corpus_root)),
                'data': _to_json_serializable(case.data),
            }
            target.write_text(
                json.dumps(payload, indent=2, sort_keys=True) + '\n',
                encoding='utf-8',
            )
            count += 1

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
    parser.add_argument('--in', dest='in_dir', required=True,
                        help='Path to the conformance corpus root.')
    parser.add_argument('--out', dest='out_dir', required=True,
                        help='Output directory for JSON mirrors.')
    args = parser.parse_args(argv)

    in_dir = Path(args.in_dir)
    out_dir = Path(args.out_dir)
    if not (in_dir / 'schema').is_dir():
        print(f'corpus_to_json: --in {in_dir} does not look like a corpus root '
              f'(no schema/ subdir)', file=sys.stderr)
        return 2
    n = convert(in_dir, out_dir)
    print(f'corpus_to_json: wrote {n} cases to {out_dir}')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
