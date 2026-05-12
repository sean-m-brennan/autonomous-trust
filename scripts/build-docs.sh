#!/bin/bash
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
#
# Build protocol documentation using the AT sequence-diagram tool.
#
# Three things happen on each run (all idempotent):
#   1. Discovery: every .md under doc/ that contains an
#      `at_diagram:start` sentinel pair is refreshed via
#      `at_diagram.py --embed`. Byte-stable when scenarios are
#      unchanged.
#   2. Generation: for every protocol that has a
#      `<protocol>-canonical.yaml` scenario, a standalone
#      `doc/architecture/_generated/<protocol>-sequence.md` file is
#      (re)written. Each generated file itself carries an
#      at_diagram:start/end marker pair so future runs keep it in
#      sync via the same embed path.
#   3. Drift check: `at_diagram.py --check` runs against every
#      unique (protocol, scenario) seen in steps 1 and 2, surfacing
#      handler-registry vs. corpus drift. Exits non-zero on any
#      drift.
#
# Usage:
#   scripts/build-docs.sh                       # text only (mermaid in markdown)
#   scripts/build-docs.sh --check-only          # skip embed/generation; drift report only
#   scripts/build-docs.sh --protocol identity   # restrict to one protocol
#   scripts/build-docs.sh --format png          # also render binaries via mmdc
#   scripts/build-docs.sh --format svg
#
# Binary formats (`--format png|svg`) require `mmdc` (mermaid-cli) on
# PATH; the script soft-warns and continues if it is missing. Mermaid
# embedding into markdown is text-only by design and never depends on
# mmdc.

set -euo pipefail

here=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)

tool="$here/src/autonomous-trust/tools/at_diagram.py"
scenarios_root="$here/src/autonomous-trust/conformance/scenarios"
doc_root="$here/doc"
generated_dir="$here/doc/architecture/_generated"

if [[ ! -f "$tool" ]]; then
  echo "ERROR: at_diagram tool not found at $tool" >&2
  exit 2
fi

# --check imports the live `autonomous_trust` package to inspect each
# protocol's handler registry; put the source root on PYTHONPATH so the
# tool can find it whether the user has the conda env active or not.
py_pkg_root="$here/src/autonomous-trust"
export PYTHONPATH="${py_pkg_root}${PYTHONPATH:+:${PYTHONPATH}}"

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------

check_only=0
format='mermaid'
only_protocol=''

while (("$#")); do
  case "$1" in
    --check-only)
      check_only=1
      shift
      ;;
    --protocol)
      only_protocol="${2:-}"
      if [[ -z "$only_protocol" ]]; then
        echo "ERROR: --protocol requires an argument." >&2
        exit 2
      fi
      shift 2
      ;;
    --format)
      format="${2:-}"
      case "$format" in
        mermaid|png|svg) ;;
        *)
          echo "ERROR: --format must be mermaid, png, or svg (got '$format')." >&2
          exit 2
          ;;
      esac
      shift 2
      ;;
    -h|--help)
      sed -n '17,46p' "$0"
      exit 0
      ;;
    *)
      echo "ERROR: unrecognized argument: $1" >&2
      exit 2
      ;;
  esac
done

# Aggregated state. Tuples are recorded as "<protocol>\t<scenario>" lines.
tuples_file=$(mktemp)
trap 'rm -f "$tuples_file"' EXIT

embed_failures=0
check_failures=0
embedded_files=0
generated_files=0
binary_renders=0

# ---------------------------------------------------------------------------
# Step 1 — discover markers and refresh in place
# ---------------------------------------------------------------------------

discover_and_embed() {
  # Files with at least one at_diagram:start marker. We always walk
  # them (to populate tuples_file for --check), but skip the embed
  # write when --check-only is set.
  local md
  while IFS= read -r md; do
    [[ -z "$md" ]] && continue
    if (( ! check_only )); then
      if ! python "$tool" --embed "$md"; then
        echo "  embed FAILED: $md" >&2
        embed_failures=$((embed_failures + 1))
        continue
      fi
      embedded_files=$((embedded_files + 1))
    fi
    # Capture (protocol, scenario) tuples from this file's markers.
    python - "$md" <<'PY' >> "$tuples_file"
import re, sys
text = open(sys.argv[1], encoding='utf-8').read()
pat = re.compile(r'<!--\s*at_diagram:start\s+(?P<attrs>.*?)\s*-->')
attr = re.compile(r'(\w+)\s*=\s*([\w\-./]+)')
for m in pat.finditer(text):
    attrs = dict(attr.findall(m.group('attrs') or ''))
    proto = attrs.get('protocol'); scen = attrs.get('scenario')
    if proto and scen:
        print(f"{proto}\t{scen}")
PY
  done < <(grep -rlF 'at_diagram:start' "$doc_root" --include='*.md' \
             --exclude-dir='_generated' 2>/dev/null || true)
}

# ---------------------------------------------------------------------------
# Step 2 — generate per-protocol standalone diagrams
# ---------------------------------------------------------------------------

protocols_with_canonical() {
  local proto_dir name
  for proto_dir in "$scenarios_root"/*/; do
    [[ -d "$proto_dir" ]] || continue
    name=$(basename "$proto_dir")
    if [[ -n "$only_protocol" && "$name" != "$only_protocol" ]]; then
      continue
    fi
    if [[ -f "$proto_dir/${name}-canonical.yaml" ]]; then
      echo "$name"
    fi
  done
}

generate_per_protocol() {
  # Always walk the protocol set so tuples_file picks up canonical
  # scenarios for --check, even under --check-only. We only skip the
  # filesystem writes when --check-only is set.
  local any_canonical=0
  local proto
  while IFS= read -r proto; do
    [[ -z "$proto" ]] && continue
    any_canonical=1
    printf '%s\t%s-canonical\n' "$proto" "$proto" >> "$tuples_file"
    if (( check_only )); then
      continue
    fi
    mkdir -p "$generated_dir"
    local out_file="$generated_dir/${proto}-sequence.md"
    if [[ ! -f "$out_file" ]] || ! grep -qF 'at_diagram:start' "$out_file"; then
      # Bootstrap: write a stub the embed step can fill in.
      cat > "$out_file" <<EOF
# ${proto^} protocol — canonical sequence

Generated by \`scripts/build-docs.sh\` from
\`src/autonomous-trust/conformance/scenarios/${proto}/${proto}-canonical.yaml\`.
Do not edit by hand; modify the scenario YAML instead.

<!-- at_diagram:start protocol=${proto} scenario=${proto}-canonical -->
<!-- at_diagram:end -->
EOF
    fi
    if ! python "$tool" --embed "$out_file"; then
      echo "  generate FAILED: $out_file" >&2
      embed_failures=$((embed_failures + 1))
      continue
    fi
    generated_files=$((generated_files + 1))
  done < <(protocols_with_canonical)

  if (( ! any_canonical )); then
    echo "  (no <protocol>-canonical.yaml scenarios found under $scenarios_root;"
    echo "   add one per protocol to populate $generated_dir.)"
  fi
}

# ---------------------------------------------------------------------------
# Step 3 — binary renders via mmdc (optional)
# ---------------------------------------------------------------------------

render_binaries() {
  if [[ "$format" == "mermaid" ]] || (( check_only )); then
    return 0
  fi
  if ! command -v mmdc >/dev/null 2>&1; then
    echo "  --format $format requested but 'mmdc' (mermaid-cli) is not on PATH."
    echo "  Install with: npm install -g @mermaid-js/mermaid-cli" >&2
    echo "  Skipping binary renders; mermaid text was already embedded above." >&2
    return 0
  fi
  # The Python mermaid-cli wrapper drives Chromium via Playwright; the
  # browser binaries live under ~/.cache/ms-playwright after a one-time
  # install. Install before the first render so a fresh env doesn't hit
  # the "Executable doesn't exist" error from Playwright.
  #
  # Browser versions are pinned per-Playwright-release; if two Playwright
  # versions exist in the env (the `playwright` CLI on PATH vs. the one
  # mmdc imports at runtime), the standalone `playwright install` can
  # download the wrong version. So derive mmdc's interpreter from its
  # shebang and run `<that python> -m playwright install` instead — it
  # uses the exact Playwright that mmdc loads, so versions can't drift.
  install_playwright_browsers() {
    local mmdc_path interp shebang
    mmdc_path=$(command -v mmdc) || return 0
    shebang=$(head -n1 "$mmdc_path" 2>/dev/null || true)
    case "$shebang" in
      "#!"*python*)
        interp="${shebang#"#!"}"
        # Strip any trailing args (rare, but pyenv-style shebangs sometimes have flags).
        interp="${interp%% *}"
        ;;
      *)
        if command -v python >/dev/null 2>&1; then
          interp=python
        else
          return 0
        fi
        ;;
    esac
    if ! "$interp" -c 'import playwright' >/dev/null 2>&1; then
      return 0  # not a Playwright-backed mmdc (e.g. npm install); skip.
    fi
    # Ask THIS Playwright where its chromium-headless-shell binary should
    # live and whether the file is there. If yes, browsers match this
    # Playwright's version → skip install. Otherwise install. This is
    # robust against the case where a prior `playwright install` from a
    # different Playwright version left behind ~/.cache/ms-playwright/
    # entries that don't match what mmdc imports at runtime.
    if "$interp" - <<'PY' >/dev/null 2>&1
import pathlib, sys
from playwright.sync_api import sync_playwright
with sync_playwright() as p:
    bp = pathlib.Path(p.chromium.executable_path)
sys.exit(0 if bp.exists() else 1)
PY
    then
      return 0
    fi
    echo "  installing Playwright browsers via $interp (matching mmdc's version) ..."
    if ! "$interp" -m playwright install; then
      echo "  WARNING: '$interp -m playwright install' failed; binary renders may fail" >&2
    fi
  }
  install_playwright_browsers
  mkdir -p "$generated_dir"
  local proto scen yaml out_file stem
  while IFS=$'\t' read -r proto scen; do
    [[ -z "$proto" || -z "$scen" ]] && continue
    yaml="$scenarios_root/$proto/${scen}.yaml"
    if [[ ! -f "$yaml" ]]; then
      echo "  skip binary: missing scenario YAML $yaml" >&2
      continue
    fi
    # Avoid `agreement-agreement-canonical.svg` when scenario name already
    # carries the protocol prefix (true for every `<proto>-canonical.yaml`).
    if [[ "$scen" == "$proto"-* ]]; then
      stem="$scen"
    else
      stem="${proto}-${scen}"
    fi
    out_file="$generated_dir/${stem}.${format}"
    if python "$tool" --format "$format" "$yaml" > "$out_file"; then
      binary_renders=$((binary_renders + 1))
    else
      echo "  binary render FAILED: $yaml -> $out_file" >&2
      rm -f "$out_file"
      embed_failures=$((embed_failures + 1))
    fi
  done < <(sort -u "$tuples_file")
}

# ---------------------------------------------------------------------------
# Step 4 — drift check on every unique (protocol, scenario)
# ---------------------------------------------------------------------------

run_check() {
  local proto scen yaml
  while IFS=$'\t' read -r proto scen; do
    [[ -z "$proto" || -z "$scen" ]] && continue
    yaml="$scenarios_root/$proto/${scen}.yaml"
    if [[ ! -f "$yaml" ]]; then
      echo "  check skip: missing scenario YAML $yaml" >&2
      check_failures=$((check_failures + 1))
      continue
    fi
    if ! python "$tool" --check "$yaml"; then
      check_failures=$((check_failures + 1))
    fi
  done < <(sort -u "$tuples_file")
}

# ---------------------------------------------------------------------------
# Drive
# ---------------------------------------------------------------------------

echo "build-docs: scanning $doc_root for at_diagram markers ..."
discover_and_embed

echo "build-docs: generating per-protocol diagrams under $generated_dir ..."
generate_per_protocol

if [[ "$format" != "mermaid" ]]; then
  echo "build-docs: rendering --format $format binaries ..."
  render_binaries
fi

if [[ -s "$tuples_file" ]]; then
  echo "build-docs: drift check on $(sort -u "$tuples_file" | wc -l | tr -d ' ') scenario(s) ..."
  run_check
else
  echo "build-docs: no scenarios referenced; skipping drift check."
fi

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

echo
echo "build-docs summary"
echo "  embedded:   $embedded_files file(s) in $doc_root"
echo "  generated:  $generated_files file(s) in $generated_dir"
if [[ "$format" != "mermaid" ]]; then
  echo "  binaries:   $binary_renders file(s) ($format)"
fi
echo "  embed/render failures: $embed_failures"
echo "  drift failures:        $check_failures"

if (( embed_failures > 0 || check_failures > 0 )); then
  exit 1
fi
exit 0
