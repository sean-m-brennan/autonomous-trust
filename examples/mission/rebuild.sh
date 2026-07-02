#!/bin/bash
# ******************
#  Copyright 2024 TekFive, Inc., Sean M. Brennan, and contributors
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

this_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" &> /dev/null && pwd)

export DOCKER_ROOT=~/Software/.docker.dir
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
