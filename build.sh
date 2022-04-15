#!/bin/bash

cd "$(dirname "$0")" || exit 1

NAME=${NAME:-kubemarine}

rm -rf build.sh documentation examples CONTRIBUTING.md .git

docker build -t "${NAME}" --build-arg VERSION=${LOCATION} --no-cache .

for id in $DOCKER_NAMES; do
    docker tag "${NAME}" "$id"
done

chmod +x kubemarine
