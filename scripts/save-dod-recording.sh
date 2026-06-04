#!/usr/bin/env bash
# ******************
#  Copyright 2025 Sean M. Brennan and contributors
#  Licensed under the Apache License, Version 2.0
# ******************
#
# Pulls the DoD squad-infiltration demo recording out of the minikube node and
# writes it to a local JSON file you can replay with scripts/play-dod-mission.sh.
#
# The live coordinator records to /data/dod-mission-recording/demo.json inside
# the cluster; this fetches it via `minikube ssh "cat ..."`.
#
# Usage:
#   scripts/save-dod-recording.sh [OUTPUT.json]
#
# Arguments:
#   OUTPUT.json   Local destination (default: dod-demo.json)
#
# Environment:
#   REMOTE_RECORDING  Path inside the node
#                     (default: /data/dod-mission-recording/demo.json)
#
# Examples:
#   scripts/save-dod-recording.sh                 # -> dod-demo.json
#   scripts/save-dod-recording.sh demo.json
#   REMOTE_RECORDING=/data/other/rec.json scripts/save-dod-recording.sh out.json

set -euo pipefail

here=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
cd "$here"

log() { printf '[save-dod-recording] %s\n' "$*"; }
err() { printf '[save-dod-recording] ERROR: %s\n' "$*" >&2; }

OUTPUT="${1:-dod-demo.json}"
REMOTE_RECORDING="${REMOTE_RECORDING:-/data/dod-mission-recording/demo.json}"

command -v minikube >/dev/null 2>&1 || { err "minikube not found in PATH."; exit 1; }

if ! minikube status >/dev/null 2>&1; then
    err "minikube does not appear to be running."
    exit 1
fi

# Verify the recording exists in the node before clobbering the local file.
if ! minikube ssh "test -f '$REMOTE_RECORDING'" >/dev/null 2>&1; then
    err "Recording not found in node: $REMOTE_RECORDING"
    err "    Has the demo run and recorded yet?"
    exit 1
fi

log "Fetching $REMOTE_RECORDING -> $OUTPUT"

# Write to a temp file first so a failed/partial transfer never overwrites a
# good local copy. `minikube ssh` adds a trailing CR on some platforms; strip
# it so the output is clean JSON.
tmp=$(mktemp "${OUTPUT}.XXXXXX")
trap 'rm -f "$tmp"' EXIT

if ! minikube ssh "cat '$REMOTE_RECORDING'" | tr -d '\r' > "$tmp"; then
    err "Failed to read recording from node."
    exit 1
fi

if [[ ! -s "$tmp" ]]; then
    err "Recording came back empty: $REMOTE_RECORDING"
    exit 1
fi

# Sanity-check it's valid JSON if a parser is handy (non-fatal if absent).
if command -v python3 >/dev/null 2>&1; then
    python3 -c "import json,sys; json.load(open(sys.argv[1]))" "$tmp" 2>/dev/null \
        || { err "Fetched data is not valid JSON."; exit 1; }
fi

mv "$tmp" "$OUTPUT"
trap - EXIT

log "Saved $(wc -c < "$OUTPUT") bytes to $OUTPUT"
log "Replay it with: scripts/play-dod-mission.sh $OUTPUT"
