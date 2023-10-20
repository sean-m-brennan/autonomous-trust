#!/bin/sh

# Optionally install visualizer
if 0; then
  docker service ls | awk '{print $2}' | grep registry
  if [ $? -ne 0 ]; then
    docker service create --name=viz --publish=8080:8080 --constraint=node.role==manager --mount=type=bind,src=/var/run/docker.sock,dst=/var/run/docker.sock dockersamples/visualizer
  fi
fi

namespace=autonomous_trust
export DOCKER_ON_DISK=/media/user/Backup/docker

cert_dir=${DOCKER_ON_DISK}/cert
openssl req -newkey rsa:4096 -nodes -sha256 -keyout $cert_dir/registry.key -x509 -days 365 -out $cert_dir/registry.crt

docker stack service ls | awk '{print $2}' | grep registry
if [ $? -ne 0 ]; then
    #docker stack deploy --compose-file ../../src/docker-registry.yaml $namespace
    docker run -d -p 5000:5000 --restart=always --name registry -v $DOCKER_ON_DISK/registry:/var/lib/registry registry:2
fi

