#!/bin/sh

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
mkdir -p "${AUTONOMOUS_TRUST_ROOT}/etc/at" "${AUTONOMOUS_TRUST_ROOT}/var/at"

debug "Launching: at_demo --generate-config --log-level ${LOG_LEVEL:-info} $*"
exec at_demo --generate-config --log-level "${LOG_LEVEL:-info}" "$@"
