#!/bin/sh

sudo ip route del default
sudo ip route add default via $ROUTER dev eth0

exec "$@"
