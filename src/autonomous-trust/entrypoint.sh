#!/bin/sh

sudo ip route del default
sudo ip route add default via $ROUTER dev eth0
ip -o -4 route show to default

exec "$@"
