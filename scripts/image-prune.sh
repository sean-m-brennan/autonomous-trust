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
# Reclaim the image generations that rebuilds orphan.
#
# Every image in the demo chain carries a FIXED tag (:dev via IMAGE_TAG in
# run-demo.sh / scale-test-dod-mission.sh, plain ${IMAGE_NAME}-* in
# build-docker.sh). A rebuild therefore moves the tag onto a new image and
# leaves the previous one dangling <none>, still pinning its whole snapshot
# chain. Six lineages (base, inspector, c, dod demo, dod peer, disaster) times
# one dead generation per rebuild is how /var/lib/docker (or /var/lib/containerd
# when the containerd snapshotter is enabled) reaches triple-digit GB.
#
# A blanket `docker image prune -f` would fix that but also delete dangling
# images this repo never created, in whichever daemon happens to be active --
# and run-demo.sh runs builds against the *minikube* daemon after
# use_cluster_docker_env(). So instead: remember the image ID each tag moved
# off, and delete exactly those, only when they are untagged and unused.
#
# Usage (sourced):
#   source "$SCRIPT_DIR/image-prune.sh"
#   build_image <ref> <docker build args...>     # in place of `docker build -t <ref> ...`
#   reclaim_superseded_images                     # once, after the chain is built
#
# Usage (standalone, read-only):
#   ./image-prune.sh report      # what a blanket `docker image prune -a` would reclaim
#
# Set AT_KEEP_SUPERSEDED=1 to build without reclaiming anything (e.g. to keep a
# previous generation around for a diff or a rollback).

# --- Logging -------------------------------------------------------------
# Sourcing scripts define their own logger under different names (log in
# run-demo.sh, info in build-docker.sh), so bind to whichever exists.
_ip_log() {
    if declare -F log >/dev/null 2>&1; then log "$@"
    elif declare -F info >/dev/null 2>&1; then info "$@"
    else echo "[image-prune] $*"
    fi
}

# IDs whose tag moved during this run, parent-before-child in build order.
AT_SUPERSEDED_IMAGES=()

# build_image <ref> <docker build args...>
#
# Wraps `docker build`, adding -t <ref> itself so <ref> can be recorded. Build
# failures propagate unchanged (the caller's `set -e` still applies), and
# nothing is reclaimed unless the build succeeds and actually moved the tag.
build_image() {
    local ref="$1"; shift
    local prev_id
    prev_id="$(docker image inspect -f '{{.Id}}' "$ref" 2>/dev/null || true)"

    docker build -t "$ref" "$@" || return $?

    local new_id
    new_id="$(docker image inspect -f '{{.Id}}' "$ref" 2>/dev/null || true)"
    if [[ -n "$prev_id" && -n "$new_id" && "$prev_id" != "$new_id" ]]; then
        AT_SUPERSEDED_IMAGES+=("$prev_id")
    fi
}

# Remove one superseded image, if it is genuinely unreferenced. Returns 0 only
# when something was deleted, so the sweep below can tell whether to re-try.
_reclaim_one() {
    local id="$1"

    # Re-tagged since (another ref now points at it) -> not ours to remove.
    local tags
    tags="$(docker image inspect -f '{{len .RepoTags}}' "$id" 2>/dev/null || echo missing)"
    [[ "$tags" == "0" ]] || return 1

    # Referenced by any container, running or exited (ancestor= also catches
    # containers created from a descendant image) -> leave it alone.
    if [[ -n "$(docker ps -aq --filter "ancestor=$id" 2>/dev/null)" ]]; then
        return 1
    fi

    # `docker image rm` refuses an image that still has dependent CHILD images,
    # which is the desired outcome, not an error: the chain is built
    # parent-first, so the old base is still the parent of the old overlay
    # until that overlay is reclaimed too. The sweep re-tries for that reason.
    local out
    out="$(docker image rm "$id" 2>/dev/null)" || return 1
    local layers
    layers="$(grep -c '^Deleted:' <<<"$out" || true)"
    _ip_log "Reclaimed superseded image ${id#sha256:}" \
            "(${layers:-0} layer(s) freed)"
    return 0
}

# Sweep every generation this run orphaned. Repeats until a pass frees nothing,
# so a parent gets reclaimed on the pass after the child that pinned it.
reclaim_superseded_images() {
    [[ "${AT_KEEP_SUPERSEDED:-0}" == "1" ]] && return 0
    (( ${#AT_SUPERSEDED_IMAGES[@]} )) || return 0

    local pending=("${AT_SUPERSEDED_IMAGES[@]}")
    local progress=1
    while (( ${#pending[@]} && progress )); do
        progress=0
        local remaining=()
        local id
        for id in "${pending[@]}"; do
            if _reclaim_one "$id"; then
                progress=1
            else
                remaining+=("$id")
            fi
        done
        pending=("${remaining[@]+"${remaining[@]}"}")
    done

    # Whatever survives is still in use (a container holds it, or it was
    # re-tagged). Say so rather than failing: an operator reading this needs to
    # know space was NOT reclaimed and why.
    if (( ${#pending[@]} )); then
        _ip_log "${#pending[@]} superseded image(s) still referenced by a" \
                "container or tag; left in place. Free them with:" \
                "docker ps -a --filter ancestor=${pending[0]#sha256:}"
    fi
    AT_SUPERSEDED_IMAGES=()
}

# --- Standalone: read-only report ---------------------------------------
# Deliberately has no destructive subcommand -- the backlog of dangling images
# from before this helper existed is `docker image prune -a` plus
# `docker builder prune -a`, which are the operator's call, not a script's.
_ip_report() {
    echo "Dangling (untagged) images in the active daemon:"
    docker image ls -f dangling=true \
        --format '  {{.ID}}  {{.Size}}\t{{.CreatedSince}}' 2>/dev/null || true
    echo
    echo "Reclaimable totals (docker system df):"
    docker system df 2>/dev/null || true
    echo
    echo "The backlog is reclaimed with, in increasing order of aggression:"
    echo "  docker image prune -a       # every dangling generation"
    echo "  docker builder prune -a     # build cache (largest win after --no-cache runs)"
    echo "  minikube delete             # the cluster's whole image store"
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    case "${1:-report}" in
        report) _ip_report ;;
        *) echo "usage: $(basename "$0") report" >&2; exit 2 ;;
    esac
fi
