#!/bin/bash

export ALLOWED_ACCESS_IDS=p-sx1lbli4qlzf
export PROXY_PORT=19414
export DNS_SERVER=`cat /etc/resolv.conf | grep nameserver | awk '{print $2}'`
export AKEYLESS_GW_URL=https://rest.akeyless.io
export LOCAL_SUBNETS=`ip addr | grep inet | awk '{print $2}' | tr '\n' ',' | sed 's/,$//'`
export DEBUG=true

./socks5-server
