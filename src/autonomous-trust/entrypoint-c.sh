#!/bin/sh

# Staggered startup delay (for multi-node demos)
if [ -n "$STARTUP_DELAY" ] && [ "$STARTUP_DELAY" -gt 0 ] 2>/dev/null; then
    echo "Waiting ${STARTUP_DELAY}s before starting..."
    sleep "$STARTUP_DELAY"
fi

mkdir -p "${AUTONOMOUS_TRUST_ROOT}/etc/at" "${AUTONOMOUS_TRUST_ROOT}/var/at"

exec at_demo --generate-config --log-level "${LOG_LEVEL:-info}" "$@"
