#!/usr/bin/env bash
# Rebuild the AutonomousTrust brag video: composition/ -> brag.mp4 -> brag.webm.
#
# The render needs the pinned hyperframes CLI (composition/package.json) plus its
# cache of chrome-headless-shell and fonts under ~/.cache/hyperframes.
#
# npm_config_ignore_scripts is required behind the sandbox proxy: the CLI pulls in
# onnxruntime-node (its Kokoro TTS backend), whose postinstall fetches a binary
# straight from github.com and ignores http_proxy, so the whole install aborts
# with ECONNREFUSED. Nothing here needs TTS -- the narration WAVs are already in
# composition/assets/voice -- so skipping postinstalls costs us nothing. Drop this
# if you ever need to regenerate the voice track.
#
#   ./build.sh              render, then transcode
#   SKIP_RENDER=1 ./build.sh   transcode an existing brag.mp4 only
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [[ "${SKIP_RENDER:-0}" != 1 ]]; then
    ( cd "$here/composition"
      export npm_config_ignore_scripts=true
      npm run check
      npm run render -- --quality delivery --output "$here/brag.mp4" )
fi

test -s "$here/brag.mp4"
ffmpeg -y -loglevel warning -i "$here/brag.mp4" \
    -c:v libvpx-vp9 -crf 32 -b:v 0 -row-mt 1 \
    -c:a libopus -b:a 128k \
    "$here/brag.webm"
ls -lh "$here/brag.mp4" "$here/brag.webm"
