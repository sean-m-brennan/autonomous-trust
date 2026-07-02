#!/bin/bash
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
#
# Launch the AutonomousTrust Operator console (PIV+MFA terminal UI).

# Run everything relative to the repo root
here=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
cd "$here" || exit 1

usage() {
  cat <<'EOF'
Usage: run-operator.sh [--demo] [operator args...] [-h|--help]

Launch the AutonomousTrust Operator console (the PIV+MFA Textual TUI in
src/autonomous-trust-operator). All arguments are forwarded verbatim to
`python -m autonomous_trust.operator`:

  run-operator.sh --demo                 # seeded directory, no live node
  run-operator.sh                        # real node bridge
  run-operator.sh --software-cert C.pem --software-key K.pem --ca-bundle CA.pem
                                         # dev activator (software token, no card)

The console needs a TTY, so run it in an interactive terminal (not piped).

Environment:
  PYTHON                      interpreter to use (default: autodetected — an
                              active env's python, else src/autonomous-trust/.venv).
  AUTONOMOUS_TRUST_BACKEND    core backend (default: python; the operator core
                              modules are python-only).

Options:
  -h, --help    Show this help message and exit.
EOF
}

case "${1:-}" in
  -h|--help) usage; exit 0 ;;
esac

src="$here/src"
# Namespace-package roots the operator imports from (core + services + operator);
# prepended so a working tree runs without an editable install.
export PYTHONPATH="$src/autonomous-trust:$src/autonomous-trust-services:$src/autonomous-trust-operator${PYTHONPATH:+:$PYTHONPATH}"
# Operator core (session/activate/resource_directory/operator_node) is python-only.
export AUTONOMOUS_TRUST_BACKEND="${AUTONOMOUS_TRUST_BACKEND:-python}"

# Pick an interpreter: explicit $PYTHON, else the active env's python if it has
# Textual, else the repo's autonomous-trust venv.
pick_python() {
  if [ -n "${PYTHON:-}" ]; then echo "$PYTHON"; return; fi
  if command -v python >/dev/null 2>&1 && \
     python -c 'import textual' >/dev/null 2>&1; then
    echo python; return
  fi
  if [ -x "$src/autonomous-trust/.venv/bin/python" ]; then
    echo "$src/autonomous-trust/.venv/bin/python"; return
  fi
  echo python
}
PY="$(pick_python)"

if ! "$PY" -c 'import textual' >/dev/null 2>&1; then
  echo "error: 'textual' is not importable with '$PY'." >&2
  echo "       Activate the dev env (conda activate autonomous_trust) or set" >&2
  echo "       PYTHON=/path/to/python, then re-run. (pip install textual pyotp)" >&2
  exit 1
fi

exec "$PY" -m autonomous_trust.operator "$@"
