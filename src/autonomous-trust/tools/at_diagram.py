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

"""at_diagram: render AutonomousTrust scenarios as Mermaid sequenceDiagrams.

Reads scenario YAMLs from the conformance corpus (the same files that drive
the test harness) and emits a Mermaid block. The shared scenario format is
the entire interface — there is no separate authoring step for diagrams,
so they cannot drift from the executable spec.

See SEQUENCE_DIAGRAM_TOOL_SPEC.md for the full specification.
"""

from __future__ import annotations

import argparse
import importlib
import json
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

import jsonschema
from ruamel.yaml import YAML


_yaml = YAML(typ='safe')


# ---------------------------------------------------------------------------
# Repository layout
# ---------------------------------------------------------------------------

# tools/ lives next to conformance/ under src/autonomous-trust/. The corpus
# root is the parent of this file's parent.
_TOOLS_DIR = Path(__file__).resolve().parent
_PROJECT_ROOT = _TOOLS_DIR.parent
CORPUS_ROOT = _PROJECT_ROOT / 'conformance'


# ---------------------------------------------------------------------------
# Mermaid rendering
# ---------------------------------------------------------------------------

@dataclass
class RenderOptions:
    annotate_state: bool = False


def render(scenario: dict[str, Any], opts: RenderOptions | None = None) -> str:
    """Render a parsed scenario dict to a Mermaid sequenceDiagram string.

    Pure function. The mapping from scenario YAML to Mermaid is exhaustively
    defined in SEQUENCE_DIAGRAM_TOOL_SPEC.md §Rendering Rules.
    """
    opts = opts or RenderOptions()
    if scenario.get('kind') != 'scenario':
        raise ValueError(
            f'expected kind: scenario, got {scenario.get("kind")!r}; the diagram '
            f'tool only renders state-machine scenarios, not vectors'
        )

    lines: list[str] = ['sequenceDiagram']

    for participant in scenario.get('participants', []):
        lines.append(f'    participant {participant["id"]} as {participant["role"]}')

    # Build the response graph: which steps are responses to which?
    # children[parent_step_id] -> set of child step ids.
    children: dict[int, list[int]] = {}
    by_id: dict[int, dict[str, Any]] = {}
    for step in scenario.get('steps', []):
        by_id[step['id']] = step
        if 'in_response_to' in step:
            children.setdefault(step['in_response_to'], []).append(step['id'])

    # Activation rule (per spec): a participant is activated on receipt of a
    # message that some later step replies to. The receiver of a step that
    # has at least one child is the activatee. Deactivation happens on the
    # FIRST reply emitted by that participant in the children set.
    deactivated_via: dict[int, int] = {}
    for parent_id, kids in children.items():
        if not kids:
            continue
        deactivated_via[parent_id] = min(kids)

    for step in scenario.get('steps', []):
        lines.extend(_render_step(step, children, deactivated_via))

    if opts.annotate_state:
        for participant_id, asserts in (scenario.get('expected_state') or {}).items():
            if participant_id == 'group':
                continue  # group state isn't anchored to a single lane
            if not isinstance(asserts, dict):
                continue
            for key, value in asserts.items():
                lines.append(
                    f'    Note over {participant_id}: state: {key}={value}'
                )

    return '\n'.join(lines) + '\n'


def _render_step(step: dict[str, Any],
                 children: dict[int, list[int]],
                 deactivated_via: dict[int, int]) -> list[str]:
    """Emit the Mermaid lines for one scenario step."""
    out: list[str] = []
    sid = step['id']
    from_id = step['from']
    to_id = step['to']
    function = step['function']
    in_resp = step.get('in_response_to')

    if to_id == 'broadcast':
        # Broadcast steps don't get arrow syntax (no single recipient lane).
        out.append(f'    Note over {from_id}: broadcast: {function}')
    else:
        activates = sid in children  # this step's recipient is activated
        deactivates = (
            in_resp is not None
            and deactivated_via.get(in_resp) == sid
            and from_id != to_id
        )
        # Mermaid arrow syntax:
        #   ->>   solid (initial)
        #   -->>  dashed (reply)
        # The +/- modifier goes between the arrow and the recipient name:
        #   A->>+B  activates B (recipient)
        #   B-->>-A deactivates B (sender, formerly the activated recipient)
        # We can only emit one modifier per arrow; activation wins if both
        # would apply (rare in well-formed traces).
        arrow = '-->>' if in_resp is not None else '->>'
        modifier = '+' if activates else ('-' if deactivates else '')
        re_clause = f' (re: {in_resp})' if in_resp is not None else ''
        out.append(f'    {from_id}{arrow}{modifier}{to_id}: {function}{re_clause}')

    desc = step.get('description')
    if desc:
        # Multi-line YAML block literals come through with newlines; collapse
        # them so the Mermaid note stays on one line. Mermaid would otherwise
        # try to interpret each newline as a new statement.
        flat = ' '.join(line.strip() for line in str(desc).splitlines() if line.strip())
        if flat:
            out.append(f'    Note right of {from_id}: {flat}')

    return out


# ---------------------------------------------------------------------------
# Scenario loading
# ---------------------------------------------------------------------------

def load_scenario(path: Path, *, validate: bool = True) -> dict[str, Any]:
    """Parse one YAML at `path`; optionally JSON-Schema-validate it."""
    with path.open('r', encoding='utf-8') as fh:
        data = _yaml.load(fh)
    if not isinstance(data, dict):
        raise ValueError(f'{path}: expected a mapping at the root')
    if validate:
        schema_path = CORPUS_ROOT / 'schema' / 'scenario.schema.json'
        if schema_path.is_file():
            with schema_path.open('r', encoding='utf-8') as fh:
                schema = json.load(fh)
            try:
                jsonschema.validate(data, schema)
            except jsonschema.ValidationError as exc:
                raise ValueError(f'{path}: schema violation: {exc.message}') from exc
    return data


def find_canonical(protocol: str) -> Path:
    """Locate a protocol's canonical scenario by convention.

    Convention: `<corpus>/scenarios/<protocol>/<protocol>-canonical.yaml`.
    Falls back to the first scenario alphabetically under the protocol dir
    if the convention file is absent.
    """
    proto_dir = CORPUS_ROOT / 'scenarios' / protocol
    if not proto_dir.is_dir():
        raise FileNotFoundError(f'no scenarios directory for protocol {protocol!r}')
    canonical = proto_dir / f'{protocol}-canonical.yaml'
    if canonical.is_file():
        return canonical
    candidates = sorted(p for p in proto_dir.glob('*.yaml') if not p.name.startswith('_'))
    if not candidates:
        raise FileNotFoundError(f'no scenarios for protocol {protocol!r}')
    return candidates[0]


def find_scenario_by_attrs(protocol: str, scenario: str) -> Path:
    """Resolve a (protocol, scenario) pair from sentinel markers to a path."""
    p = CORPUS_ROOT / 'scenarios' / protocol / f'{scenario}.yaml'
    if not p.is_file():
        raise FileNotFoundError(f'no scenario {scenario!r} for protocol {protocol!r}')
    return p


# ---------------------------------------------------------------------------
# Embed mode
# ---------------------------------------------------------------------------

_OPEN_MARKER = re.compile(
    r'<!--\s*at_diagram:start\s+(?P<attrs>.*?)\s*-->'
)
_CLOSE_MARKER = re.compile(r'<!--\s*at_diagram:end\s*-->')
_ATTR_RE = re.compile(r'(\w+)\s*=\s*([\w\-./]+)')


def embed(markdown_path: Path) -> bool:
    """Replace every `at_diagram:start ... :end` block with a fresh render.

    Idempotent: re-running against an unchanged scenario produces an
    unchanged file. Errors out (returns False, prints diagnostic) if any
    open marker has no matching close marker. Multiple marker pairs in the
    same file are processed independently.
    """
    text = markdown_path.read_text(encoding='utf-8')
    pieces: list[str] = []
    cursor = 0
    while True:
        m = _OPEN_MARKER.search(text, cursor)
        if m is None:
            pieces.append(text[cursor:])
            break
        # Find the matching close after this open
        close = _CLOSE_MARKER.search(text, m.end())
        if close is None:
            print(f'{markdown_path}: open marker at offset {m.start()} has no '
                  f'matching <!-- at_diagram:end --> marker', file=sys.stderr)
            return False
        attrs = dict(_ATTR_RE.findall(m.group('attrs') or ''))
        protocol = attrs.get('protocol')
        scenario = attrs.get('scenario')
        if not protocol or not scenario:
            print(f'{markdown_path}: open marker missing protocol= or scenario= '
                  f'attribute (got {attrs})', file=sys.stderr)
            return False
        try:
            yaml_path = find_scenario_by_attrs(protocol, scenario)
            data = load_scenario(yaml_path)
            mermaid = render(data)
        except (FileNotFoundError, ValueError) as exc:
            print(f'{markdown_path}: {exc}', file=sys.stderr)
            return False

        # Compose: keep the open marker tag, replace the block in between,
        # keep the close marker tag.
        pieces.append(text[cursor:m.end()])
        pieces.append(f'\n```mermaid\n{mermaid}```\n')
        pieces.append(text[close.start():close.end()])
        cursor = close.end()

    new_text = ''.join(pieces)
    if new_text != text:
        markdown_path.write_text(new_text, encoding='utf-8')
    return True


# ---------------------------------------------------------------------------
# --check mode
# ---------------------------------------------------------------------------

@dataclass
class CheckReport:
    unrecognized_functions: list[str]
    unexercised_functions: list[str]
    schema_violations: list[str]

    @property
    def is_clean(self) -> bool:
        return not (self.unrecognized_functions
                    or self.unexercised_functions
                    or self.schema_violations)


_PROTOCOL_CLASSES = {
    'identity': 'autonomous_trust.core.identity.protocol.IdentityProtocol',
    'reputation': 'autonomous_trust.core.reputation.protocol.ReputationProtocol',
    'negotiation': 'autonomous_trust.core.negotiation.protocol.NegotiationProtocol',
    # agreement and network do not have a class-attribute message vocabulary.
}

# Process modules that register handlers against the protocol classes above.
# Used to filter "orphan" enum entries — Protocol class attributes that have
# no `register_handler` call pointing at them.
_PROCESS_SOURCES = {
    'identity': 'autonomous_trust.core._python.identity.idprocess',
    'reputation': 'autonomous_trust.core._python.reputation.repprocess',
    'negotiation': 'autonomous_trust.core._python.negotiation.negprocess',
}


def _handler_keyed_attrs(protocol: str, attr_names: set[str]) -> set[str]:
    """Return the subset of `attr_names` actually used as `register_handler` keys.

    Reads the corresponding `*process.py` source and looks for
    `register_handler(<ProtocolClass>.<attr>, ...)` calls. Class attributes
    that the production code never registers a handler for are orphans
    (e.g. constants reserved for future use, or message names registered
    on the wire but ignored by the receiver), and should not count as
    "registered functions" for drift-check purposes.
    """
    qual = _PROCESS_SOURCES.get(protocol)
    if qual is None:
        # No process module mapped → fall back to "everything is wired".
        return set(attr_names)
    try:
        module = importlib.import_module(qual)
    except ImportError:
        return set(attr_names)
    source_path = Path(getattr(module, '__file__', '') or '')
    if not source_path.is_file():
        return set(attr_names)
    text = source_path.read_text(encoding='utf-8')
    proto_cls = _PROTOCOL_CLASSES[protocol].rsplit('.', 1)[1]
    pat = re.compile(
        rf'\bregister_handler\s*\(\s*{re.escape(proto_cls)}\.(\w+)\b'
    )
    used = {m.group(1) for m in pat.finditer(text)}
    return attr_names & used


def _registered_functions(protocol: str) -> set[str]:
    """Return the set of function-name strings the protocol class defines.

    Reads the class attributes of the matching `<Protocol>` subclass. Each
    public, all-lowercase, string-valued class attribute is treated as a
    candidate message function, then filtered to only those whose attribute
    name appears as a `register_handler(<ProtocolClass>.<attr>, ...)` key in
    the production process module. Orphan enum entries (no handler wired)
    are excluded so the drift report tracks real coverage gaps only.
    """
    qual = _PROTOCOL_CLASSES.get(protocol)
    if qual is None:
        return set()
    module_name, class_name = qual.rsplit('.', 1)
    module = importlib.import_module(module_name)
    cls = getattr(module, class_name)
    candidate_attrs: dict[str, str] = {}
    for name, value in vars(cls).items():
        if name.startswith('_'):
            continue
        if isinstance(value, str):
            candidate_attrs[name] = value
    wired_attrs = _handler_keyed_attrs(protocol, set(candidate_attrs))
    return {candidate_attrs[a] for a in wired_attrs}


def _scenarios_for_protocol(protocol: str) -> list[Path]:
    proto_dir = CORPUS_ROOT / 'scenarios' / protocol
    if not proto_dir.is_dir():
        return []
    return sorted(p for p in proto_dir.glob('*.yaml') if not p.name.startswith('_'))


def check(scenario_path: Path) -> CheckReport:
    """Cross-validate a scenario against the implementation's handler registry."""
    schema_violations: list[str] = []
    try:
        data = load_scenario(scenario_path, validate=True)
    except ValueError as exc:
        schema_violations.append(str(exc))
        return CheckReport([], [], schema_violations)

    protocol = data['protocol']
    registered = _registered_functions(protocol)

    used_in_scenario = {step['function'] for step in data.get('steps', [])}
    unrecognized = sorted(used_in_scenario - registered) if registered else []

    # Unexercised: registered functions never used by any scenario for this
    # protocol. Walk every scenario in the directory to compute the union.
    used_anywhere: set[str] = set()
    for path in _scenarios_for_protocol(protocol):
        try:
            other = load_scenario(path, validate=False)
        except (ValueError, OSError):
            continue
        used_anywhere.update(step['function'] for step in other.get('steps', []))
    unexercised = sorted(registered - used_anywhere) if registered else []

    return CheckReport(unrecognized, unexercised, schema_violations)


# ---------------------------------------------------------------------------
# Format conversion (png/svg via mmdc)
# ---------------------------------------------------------------------------

def _convert_with_mmdc(mermaid: str, fmt: str) -> bytes:
    """Shell out to mermaid-cli (`mmdc`) for png/svg rendering.

    Requires `mmdc` on PATH. The tool itself does not bundle a renderer.
    """
    if shutil.which('mmdc') is None:
        raise RuntimeError(
            'mmdc not found on PATH; install mermaid-cli (`npm install -g @mermaid-js/mermaid-cli`) '
            'to render png or svg, or use --format mermaid (default).'
        )
    import tempfile
    with tempfile.TemporaryDirectory() as td:
        td_path = Path(td)
        src = td_path / 'in.mmd'
        dst = td_path / f'out.{fmt}'
        src.write_text(mermaid, encoding='utf-8')
        proc = subprocess.run(['mmdc', '-i', str(src), '-o', str(dst)],
                              capture_output=True, text=True)
        if proc.returncode != 0:
            # Surface mmdc's actual diagnostic; the swallowed stderr is the
            # most common reason build-docs.sh users can't tell why a render
            # failed (sandbox issues under containerized Chromium, mermaid
            # syntax incompatibilities, missing puppeteer config, etc.).
            details = '\n'.join(part for part in (proc.stdout, proc.stderr) if part).strip()
            raise RuntimeError(
                f'mmdc exited {proc.returncode} for {fmt} render. '
                f'Mermaid source:\n{mermaid}\nmmdc output:\n{details or "(empty)"}'
            )
        return dst.read_bytes()


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog='at_diagram',
        description='Render AutonomousTrust scenarios as Mermaid sequenceDiagrams.',
    )
    target = p.add_mutually_exclusive_group(required=True)
    target.add_argument('scenario', nargs='?',
                        help='Path to a scenario YAML to render to stdout.')
    target.add_argument('--protocol', metavar='NAME',
                        help='Render the canonical scenario for a protocol.')
    target.add_argument('--embed', metavar='MARKDOWN',
                        help='Replace at_diagram blocks in a Markdown file.')
    target.add_argument('--check', metavar='SCENARIO',
                        help='Validate a scenario against the implementation.')
    p.add_argument('--format', choices=['mermaid', 'png', 'svg'], default='mermaid',
                   help='Output format. Default: mermaid (text).')
    p.add_argument('--annotate-state', action='store_true',
                   help='Append "Note over <id>: state: ..." lines from expected_state.')
    return p


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.check:
        report = check(Path(args.check))
        if report.is_clean:
            print(f'{args.check}: clean')
            return 0
        for v in report.schema_violations:
            print(f'{args.check}: SCHEMA: {v}', file=sys.stderr)
        for fn in report.unrecognized_functions:
            print(f'{args.check}: UNRECOGNIZED FUNCTION: {fn}', file=sys.stderr)
        for fn in report.unexercised_functions:
            print(f'{args.check}: UNEXERCISED: {fn} (no scenario uses it)', file=sys.stderr)
        return 1

    if args.embed:
        ok = embed(Path(args.embed))
        return 0 if ok else 1

    if args.protocol:
        path = find_canonical(args.protocol)
    else:
        path = Path(args.scenario)

    data = load_scenario(path)
    mermaid = render(data, RenderOptions(annotate_state=args.annotate_state))

    if args.format == 'mermaid':
        sys.stdout.write(mermaid)
        return 0
    out = _convert_with_mmdc(mermaid, args.format)
    sys.stdout.buffer.write(out)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
