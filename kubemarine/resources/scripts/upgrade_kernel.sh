#!/bin/bash
set -e

if command -v apt-get &>/dev/null; then
    apt-get update -q
    apt-get install -yq --only-upgrade linux-image-generic linux-headers-generic
elif command -v dnf &>/dev/null; then
    dnf upgrade -y kernel
elif command -v yum &>/dev/null; then
    yum upgrade -y kernel
fi
