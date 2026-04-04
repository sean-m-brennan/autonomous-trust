#!/bin/sh
# ******************
#  Copyright 2025 Sean M. Brennan and contributors
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

debug() { [ "${ENTRYPOINT_DEBUG:-0}" = "1" ] && echo "[entrypoint-c] $*"; }

debug "Starting (pid $$) at $(date -u +%Y-%m-%dT%H:%M:%SZ)"
debug "AUTONOMOUS_TRUST_ROOT=${AUTONOMOUS_TRUST_ROOT:-<unset>}"
debug "LOG_LEVEL=${LOG_LEVEL:-info}"
debug "STARTUP_DELAY=${STARTUP_DELAY:-0}"
debug "args: $*"

# Staggered startup delay (for multi-node demos)
if [ -n "$STARTUP_DELAY" ] && [ "$STARTUP_DELAY" -gt 0 ] 2>/dev/null; then
    debug "Waiting ${STARTUP_DELAY}s before starting..."
    sleep "$STARTUP_DELAY"
fi

debug "Creating directories..."
mkdir -p "${AUTONOMOUS_TRUST_ROOT}/etc/at" "${AUTONOMOUS_TRUST_ROOT}/var/at" 2>/dev/null || true

AT_DEMO="${AUTONOMOUS_TRUST_ROOT:-}/opt/autonomous-trust/bin/at_demo"
if [ ! -x "$AT_DEMO" ]; then
    AT_DEMO="$(command -v at_demo 2>/dev/null || echo at_demo)"
fi
debug "Launching: $AT_DEMO --generate-config --log-level ${LOG_LEVEL:-info} $*"
exec "$AT_DEMO" --generate-config --log-level "${LOG_LEVEL:-info}" "$@"
