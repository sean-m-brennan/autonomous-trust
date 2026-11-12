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
# Clone the select-access repos into their places in this checkout, as if they
# were submodules (they are not; AT's .gitignore keeps them out of the public
# tree). These are private TekFive repos: a clone fails for anyone without
# read access, and the script says so and carries on with the rest. A path
# that already holds a git checkout is left alone. Exits non-zero if any
# clone failed.

here=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)

repos=(
    "doc/tekfive              git@github.com:TekFive/autonomous-trust-doc.git"
    "proprietary/proxy-gateway git@github.com:TekFive/autonomous-trust-proxy-gateway.git"
    "embedded                 git@github.com:TekFive/autonomous-trust-embedded.git"
)

failed=0
for entry in "${repos[@]}"; do
    read -r path url <<< "$entry"
    dest="$here/$path"
    if [[ -e "$dest/.git" ]]; then
        echo "$path: already cloned, skipping"
        continue
    fi
    if [[ -d "$dest" && -n "$(ls -A -- "$dest")" ]]; then
        echo "$path: exists and is not a git checkout; move it aside first" >&2
        failed=1
        continue
    fi
    echo "$path: cloning $url"
    if ! git clone -- "$url" "$dest"; then
        echo "$path: clone failed (no access to $url?)" >&2
        failed=1
    fi
done
exit $failed
