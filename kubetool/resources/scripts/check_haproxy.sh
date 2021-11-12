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


# Script simply checks that ports 80, 443 and 6443 are listened by haproxy process

HAPROXY_PROC_NAME='haproxy'

for port in 80 443 6443; do
  if ! ss -ntpl sport = :${port} | grep ${HAPROXY_PROC_NAME}; then
    echo "Haproxy do not listen on port $port"
    exit 1
  fi
done