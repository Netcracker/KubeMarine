#!/bin/bash
# Copyright 2021 NetCracker Technology Corporation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.


cd "$(dirname "$0")" || exit 1

NAME=${NAME:-kubetools}

if [[ -n "${LOCATION}" ]]; then
  sed -i "s|non-release version|version ${LOCATION} build $(date +"%D %T")|g" "kubetool/__main__.py"
fi

rm -rf build.sh documentation examples CONTRIBUTING.md .git

docker build -t "${NAME}" --no-cache .

for id in $DOCKER_NAMES; do
    docker tag "${NAME}" "$id"
done

chmod +x kubetools
