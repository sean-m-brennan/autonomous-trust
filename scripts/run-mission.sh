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
#
# Prep tilt to run multiple autonomous-trust nodes

# Run everything relative to the repo root
here=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
cd "$here" || exit 1

export MINIKUBE_DRIVER=docker
#export MINIKUBE_DRIVER=kvm2
local_cpu_total=$(lscpu | grep "^CPU(s):" | awk '{print $2}')
export MINIKUBE_CPUS=$((local_cpu_total / 2))
#export MINIKUBE_ADDONS="registry,metrics-server,dashboard,ingress,ingress-dns,storage-provisioner,default-storageclass"
#export MINIKUBE_ADDONS="registry,metrics-server,dashboard,storage-provisioner,default-storageclass"
#export MINIKUBE_ADDONS="registry,metrics-server,dashboard"
export MINIKUBE_ADDONS="registry"

scripts/build.sh --py --dist

export NUM_PARTICIPANTS=6
export AUTONOMOUS_TRUST_CFG_BASE=$here/examples/mission

function cleanup {
  minikube delete
}
trap cleanup EXIT

if echo "$@" | grep with-docker >/dev/null; then
  docker network create autonomous-trust-net
  # start a registry
  docker compose config/docker-registry-compose.yaml up -d
else  # using minikube
  nfs_volume=$(echo "$@" | grep with-docker >/dev/null)
  source config/minikube.rc start || exit 1
  #kubectl wait --for=condition=Ready deployment/ingress-nginx-controller -n ingress-nginx
  kubectl port-forward --namespace kube-system svc/registry 5000:80 &

  # The host's IP inside the cluster
  CLUSTER_HOST_IP=$(minikube ssh 'ip r | grep default' | tr '\n\r' ' ' | awk '{print $3}')
  export CLUSTER_HOST_IP
  # This should be the gateway to the minikube network
  ROUTER=$(minikube ip)
  export ROUTER
  # The CIDR of the cluster network
  CLUSTER_NET=${ROUTER%.*}.0/24
  export CLUSTER_NET

  if $nfs_volume; then
    export SRC_DIR=$AUTONOMOUS_TRUST_SRC
    export CFG_DIR=$AUTONOMOUS_TRUST_CFG_BASE

    # Prerequisite:
    #   apt install nfs-kernel-server nfs-common
    #   envsubst <config/etc.exports.in >exports
    #   cp exports /etc/exports
    #   systemctl restart nfs-kernel-server
    # Confirm mount in minikube
    minikube ssh "showmount -e $CLUSTER_HOST_IP"
  else
    export SRC_DIR=/data/src
    export CFG_DIR=/data/cfg
    minikube mount --uid $FS_UID --gid $FS_GID "$AUTONOMOUS_TRUST_SRC:$SRC_DIR" &
    minikube mount --uid $FS_UID --gid $FS_GID "$AUTONOMOUS_TRUST_CFG_BASE:$CFG_DIR" &
  fi
fi

export FS_UID=$(id -u)
export FS_GID=$(id -g)

tilt up -- $@
# Blocks until killed (Ctl-C)

tilt down -- $@
