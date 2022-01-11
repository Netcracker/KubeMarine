#!/bin/bash

cd "$(dirname "$0")" || exit 1

NAME=${NAME:-kubemarine}

if [[ -n "${LOCATION}" ]]; then
  sed -i "s|non-release version|version ${LOCATION} build $(date +"%D %T")|g" "kubemarine/__main__.py"
fi

rm -rf build.sh documentation examples CONTRIBUTING.md .git

docker build -t "${NAME}" --no-cache .

for id in $DOCKER_NAMES; do
    docker tag "${NAME}" "$id"
done

chmod +x kubemarine
