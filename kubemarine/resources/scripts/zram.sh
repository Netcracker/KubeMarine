#!/bin/bash

if command -v apt-get &>/dev/null; then
    apt-get install -yq linux-modules-extra-$(uname -r)
elif command -v dnf &>/dev/null; then
    dnf install -y kernel-modules-extra
elif command -v yum &>/dev/null; then
    yum install -y kernel-modules-extra
fi

modprobe zram
mkdir -p /var/log/pods
