#!/bin/bash

# Script simply checks that ports 80, 443 and 6443 are listened by haproxy process

HAPROXY_PROC_NAME='haproxy'

for port in 80 443 6443; do
  if ! ss -ntpl sport = :${port} | grep ${HAPROXY_PROC_NAME}; then
    echo "Haproxy do not listen on port $port"
    exit 1
  fi
done