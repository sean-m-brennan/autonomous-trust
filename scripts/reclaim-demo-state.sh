#!/usr/bin/env bash
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
# Give a demo state dir (e.g. .demo-state/dod-mission) back to the host user.
#
#   scripts/reclaim-demo-state.sh DIR
#
# The demo containers run as root and rewrite files in their bind-mounted state
# dir as root, some mode 0600 (the C nodes' etc/at group/network configs). The
# seeder runs as the host user and rewrites each peer's group.cfg.json on every
# run, so a warm restart after a container run fails with PermissionError. This
# chowns the dir back through a throwaway root container, on the HOST docker
# daemon (a minikube docker-env would bind-mount a path inside the VM).
#
# Best-effort: always exits 0. When the chown can't be done it says how to do it
# by hand, and the seeder's own error follows.
set -uo pipefail

dir=${1:?usage: $0 DIR}
[[ -d "$dir" ]] || exit 0
dir=$(cd -- "$dir" && pwd)
uid=$(id -u)
gid=$(id -g)

foreign() { [[ -n "$(find "$dir" ! -user "$uid" -print -quit 2>/dev/null)" ]]; }

foreign || exit 0
echo "Reclaiming container-owned files under $dir ..."
env -u DOCKER_HOST -u DOCKER_TLS_VERIFY -u DOCKER_CERT_PATH -u MINIKUBE_ACTIVE_DOCKERD \
    docker run --rm -v "$dir:/s" alpine chown -R "$uid:$gid" /s >/dev/null 2>&1
if foreign; then
    echo "warning: some files under $dir are still not yours; the seeder may" \
         "fail with PermissionError. Fix by hand: sudo chown -R $uid:$gid '$dir'" >&2
fi
exit 0
