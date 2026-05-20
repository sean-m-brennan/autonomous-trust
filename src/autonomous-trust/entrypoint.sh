#!/bin/bash
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

# >>> conda initialize >>>
__conda_setup="$('/opt/conda/bin/conda' 'shell.bash' 'hook' 2> /dev/null)"
if [ $? -eq 0 ]; then
    eval "$__conda_setup"
else
    if [ -f "/opt/conda/etc/profile.d/conda.sh" ]; then
        . "/opt/conda/etc/profile.d/conda.sh"
    else
        export PATH="/opt/conda/bin:$PATH"
    fi
fi
unset __conda_setup
# <<< conda initialize <<<

# Staggered startup delay (for multi-node demos)
if [ -n "$STARTUP_DELAY" ] && [ "$STARTUP_DELAY" -gt 0 ] 2>/dev/null; then
    echo "Waiting ${STARTUP_DELAY}s before starting..."
    sleep "$STARTUP_DELAY"
fi

# FIXME is this necessary?
#if command -v ip >/dev/null 2>&1 && command -v sudo >/dev/null 2>&1; then
#    sudo ip route del default 2>/dev/null
#    sudo ip route add default via $ROUTER dev eth0 2>/dev/null
#    ip -o -4 route show to default
#fi

export PYTHONPATH="/app:$PYTHONPATH"
#conda run -n autonomous_trust pip3 install --upgrade pip wheel setuptools requests protobuf

# Activate the autonomous_trust conda environment if it exists; fall
# back to the base env (already initialized via the conda hook above)
# otherwise. The Dockerfile-native pip-installs deps into base and
# never creates the named env, so the original `conda activate
# autonomous_trust` printed `EnvironmentNameNotFound` on every
# container start and polluted stderr / our diagnostics. See BUGS.md
# entry "Dockerfile-native does not create autonomous_trust conda env"
# for the proper fix (RUN `conda env create -f environment.yaml`).
if conda env list 2>/dev/null | awk '{print $1}' | grep -qx autonomous_trust; then
    conda activate autonomous_trust
fi

export AUTONOMOUS_TRUST_EXE="${AUTONOMOUS_TRUST_EXE:-"-m autonomous_trust"}"
# Use CMD args ($@) if provided, otherwise fall back to AUTONOMOUS_TRUST_ARGS env var
if [ $# -eq 0 ] && [ -n "${AUTONOMOUS_TRUST_ARGS:-}" ]; then
    set -- $AUTONOMOUS_TRUST_ARGS
fi
export POSTMORTEM="${POSTMORTEM:-"false"}"
if [ "$POSTMORTEM" = "true" ]; then
    # waits for manual shutdown (will not fail); cannot exec
    # FIXME does not work as intended on error
    python3 $AUTONOMOUS_TRUST_EXE "$@" || (trap : TERM INT; sleep infinity & wait)
else
    exec python3 $AUTONOMOUS_TRUST_EXE "$@"
fi
