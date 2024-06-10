#!/bin/bash

this_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" &> /dev/null && pwd)

export DOCKER_ROOT=/media/user/Backup/docker
#nocache="--no-cache"
nocache=

cd $this_dir/../..
docker compose -f src/docker-registry.yaml up -d

docker build $nocache -t autonomous-trust-devel -f src/autonomous-trust/Dockerfile-devel .
docker tag autonomous-trust-devel:latest autonomous-trust.tekfive.com:5000/autonomous-trust-devel:latest
docker push autonomous-trust.tekfive.com:5000/autonomous-trust-devel:latest

docker build $nocache -t autonomous-trust-full-devel  -f src/Dockerfile-devel .
docker tag autonomous-trust-full-devel:latest autonomous-trust.tekfive.com:5000/autonomous-trust-full-devel:latest
docker push autonomous-trust.tekfive.com:5000/autonomous-trust-full-devel:latest

docker compose -f src/docker-registry.yaml down
