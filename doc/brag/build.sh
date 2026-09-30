#!/usr/bin/env bash
# Rebuild the AutonomousTrust brag video:
#   composition/ -> brag.mp4 -> poster -> brag.webm
#
# The render needs Node >= 22 plus the pinned hyperframes CLI
# (composition/package.json) and its cache of chrome-headless-shell and fonts
# under ~/.cache/hyperframes.
#
# npm_config_ignore_scripts is required behind the sandbox proxy: the CLI pulls in
# onnxruntime-node (its Kokoro TTS backend), whose postinstall fetches a binary
# straight from github.com and ignores http_proxy, so the whole install aborts
# with ECONNREFUSED. Nothing here needs TTS -- the narration WAVs are already in
# composition/assets/voice -- so skipping postinstalls costs us nothing. Drop this
# if you ever need to regenerate the voice track.
#
#   ./build.sh                 render, poster, transcode
#   SKIP_RENDER=1 ./build.sh   poster + transcode from an existing brag.mp4
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Node >= 22 is required (the system Node is 18; Sean manages Node with nvm).
# Resolve the newest installed major >= 22 rather than pinning one patch release,
# so this keeps working after an nvm upgrade.
if ! node --version 2>/dev/null | grep -qE '^v(2[2-9]|[3-9][0-9])\.'; then
    node_bin=$(ls -d "$HOME"/.nvm/versions/node/v* 2>/dev/null \
        | sed 's|.*/v||' | sort -t. -k1,1n -k2,2n -k3,3n \
        | awk -F. '$1 >= 22' | tail -1)
    [[ -n "$node_bin" ]] || { echo "need Node >= 22; none found under ~/.nvm" >&2; exit 1; }
    export PATH="$HOME/.nvm/versions/node/v$node_bin/bin:$PATH"
fi
export npm_config_ignore_scripts=true

# The poster: the settled divergence frame, which is the thesis image of the
# piece -- two peers whose reputation lines have just parted. brag-plan.md picks
# the moment; keep the two in step if either changes.
POSTER_AT="${POSTER_AT:-26.8}"

if [[ "${SKIP_RENDER:-0}" != 1 ]]; then
    ( cd "$here/composition"
      npm run check
      npm run render -- --quality delivery --output "$here/brag.mp4" )
fi

test -s "$here/brag.mp4"

# Pull the poster, then attach it as MP4 cover art so thumbnail grabbers use it
# instead of sampling the dark opening field. This is a stream copy: the video is
# not re-encoded, so it costs no quality and no render. (The alternative, baking
# the poster over frame 0, needs a full libx264 pass for one frame.)
ffmpeg -y -loglevel warning -ss "$POSTER_AT" -i "$here/brag.mp4" \
    -frames:v 1 -update 1 -q:v 2 "$here/brag.jpg"
ffmpeg -y -loglevel warning -i "$here/brag.mp4" -i "$here/brag.jpg" \
    -map 0:v:0 -map 0:a:0 -map 1 -c:v:0 copy -c:a copy -c:v:1 mjpeg -disposition:v:1 attached_pic \
    "$here/brag.poster.mp4"
mv "$here/brag.poster.mp4" "$here/brag.mp4"

# webm carries video + audio only; the mjpeg cover stream is dropped.
ffmpeg -y -loglevel warning -i "$here/brag.mp4" -map 0:v:0 -map 0:a:0 \
    -c:v libvpx-vp9 -crf 32 -b:v 0 -row-mt 1 \
    -c:a libopus -b:a 128k \
    "$here/brag.webm"

ls -lh "$here/brag.mp4" "$here/brag.jpg" "$here/brag.webm"
