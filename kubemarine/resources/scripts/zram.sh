#!/bin/bash

apt install -yq linux-modules-extra-$(uname -r)
modprobe zram
mkdir -p /var/log/pods
