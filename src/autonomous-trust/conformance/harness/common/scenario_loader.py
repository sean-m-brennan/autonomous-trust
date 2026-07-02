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

"""Scenario / vector loader for the AT conformance corpus.

Walks `scenarios/` and `vectors/` under a corpus root, parses each YAML,
validates against the schema for its `kind`, and resolves fixture references
into a typed `Case` record ready for adapter dispatch.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import jsonschema
from ruamel.yaml import YAML


_yaml = YAML(typ='safe')


_REF_RE = re.compile(r'^<ref:([a-zA-Z_][a-zA-Z0-9_.]*)>$')


@dataclass
class Case:
    """A parsed, schema-validated, fixture-resolved corpus case."""
    kind: str
    protocol: str
    name: str
    source_path: Path
    data: dict[str, Any]
    case_id: str = field(init=False)

    def __post_init__(self) -> None:
        digest = hashlib.sha256(self.source_path.read_bytes()).hexdigest()[:6]
        self.case_id = f"{self.protocol}/{self.name}#{digest}"


class CorpusLoadError(Exception):
    """Raised when a corpus file cannot be parsed, validated, or resolved."""


def _load_schemas(schema_dir: Path) -> dict[str, dict[str, Any]]:
    schemas: dict[str, dict[str, Any]] = {}
    for kind in ('scenario', 'wire_vector', 'crypto_vector', 'negative', 'agreement_vector'):
        path = schema_dir / f'{kind}.schema.json'
        if not path.is_file():
            raise CorpusLoadError(f'Missing schema: {path}')
        with path.open('r', encoding='utf-8') as fh:
            schemas[kind] = json.load(fh)
    return schemas


def _resolve_refs(node: Any, fixtures: dict[str, Any]) -> Any:
    if isinstance(node, str):
        m = _REF_RE.match(node)
        if not m:
            return node
        path = m.group(1).split('.')
        cursor: Any = {'fixtures': fixtures}
        for part in path:
            if not isinstance(cursor, dict) or part not in cursor:
                raise CorpusLoadError(f'Unresolvable reference <ref:{m.group(1)}>')
            cursor = cursor[part]
        return cursor
    if isinstance(node, dict):
        return {k: _resolve_refs(v, fixtures) for k, v in node.items()}
    if isinstance(node, list):
        return [_resolve_refs(v, fixtures) for v in node]
    return node


def _validate(doc: dict[str, Any], schemas: dict[str, dict[str, Any]], path: Path) -> None:
    kind = doc.get('kind')
    if kind not in schemas:
        raise CorpusLoadError(f'{path}: unknown or missing kind {kind!r}')
    try:
        jsonschema.validate(doc, schemas[kind])
    except jsonschema.ValidationError as exc:
        raise CorpusLoadError(f'{path}: schema violation: {exc.message}') from exc


def _parse_yaml(path: Path) -> dict[str, Any]:
    with path.open('r', encoding='utf-8') as fh:
        doc = _yaml.load(fh)
    if not isinstance(doc, dict):
        raise CorpusLoadError(f'{path}: expected a mapping at the root')
    return doc


def load_case(path: Path, schemas: dict[str, dict[str, Any]]) -> Case:
    """Parse one YAML at `path`, validate, and resolve `<ref:...>` tokens."""
    doc = _parse_yaml(path)
    _validate(doc, schemas, path)
    fixtures = doc.get('fixtures', {}) or {}
    resolved = _resolve_refs(doc, fixtures)
    return Case(
        kind=resolved['kind'],
        protocol=resolved['protocol'],
        name=resolved['name'],
        source_path=path,
        data=resolved,
    )


def discover(corpus_root: Path) -> list[Case]:
    """Walk `scenarios/` and `vectors/` under `corpus_root`, return validated cases.

    Order is stable: alphabetical by relative path. Hidden files and files
    starting with `_` are skipped (the latter by convention is for in-progress
    or test-only fixtures).
    """
    corpus_root = corpus_root.resolve()
    schemas = _load_schemas(corpus_root / 'schema')
    cases: list[Case] = []
    for sub in ('scenarios', 'vectors'):
        root = corpus_root / sub
        if not root.is_dir():
            continue
        for path in sorted(root.rglob('*.yaml')):
            if path.name.startswith(('.', '_')):
                continue
            cases.append(load_case(path, schemas))
    return cases


def load_testdata_bytes(corpus_root: Path, ref: str) -> bytes:
    """Resolve a `testdata/...` path under the corpus root and return its bytes."""
    p = (corpus_root / ref).resolve()
    if corpus_root not in p.parents and p != corpus_root:
        raise CorpusLoadError(f'Refusing to read outside corpus root: {ref}')
    if not p.is_file():
        raise CorpusLoadError(f'testdata file not found: {ref}')
    return p.read_bytes()


def load_testdata_text(corpus_root: Path, ref: str, encoding: str = 'utf-8') -> str:
    return load_testdata_bytes(corpus_root, ref).decode(encoding)


def hex_to_bytes(s: str) -> bytes:
    """Decode a 0x-prefixed hex string to bytes. Empty allowed (yields b'')."""
    if not isinstance(s, str) or not s.startswith('0x'):
        raise CorpusLoadError(f'expected 0x-prefixed hex, got {s!r}')
    return bytes.fromhex(s[2:])
