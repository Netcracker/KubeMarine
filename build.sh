#!/bin/bash

cd "$(dirname "$0")" || exit 1

NAME=${NAME:-kubemarine}

if [[ -n "${LOCATION}" ]]; then
  sed -i "s|non-release version|version ${LOCATION} build $(date +"%D %T")|g" "kubemarine/__main__.py"
fi

rm -rf build.sh documentation examples CONTRIBUTING.md .git bin/kubemarine.cmd requirements_nt.txt

docker build -t "${NAME}" --no-cache .

for id in $DOCKER_NAMES; do
    docker tag "${NAME}" "$id"
done

docker build -t "${NAME}_binary" --build-arg BUILD_TYPE=binary --no-cache .
CONTAINER_ID=$(docker create "${NAME}_binary")
docker cp "$CONTAINER_ID:/opt/kubemarine/dist/kubemarine" kubemarine
docker rm -v "${CONTAINER_ID}"

chmod +x kubemarine
