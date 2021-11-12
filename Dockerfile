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

FROM python:3.9-slim-buster
# Warning! Python and Debian versions should be strict to avoid sudden components upgrade,
# including unreasonable upgrade of GLIBC version. If the GLIBC version suddenly goes up, a large number of consumers
# will suddenly be unable to use the compiled binary version on older systems.

ARG BUILD_TYPE

USER root

# Used in Ansible plugin. See Ansible documentation for more details
ENV ANSIBLE_HOST_KEY_CHECKING False

COPY . /opt/kubetools/
WORKDIR /opt/kubetools/

RUN apt update && apt install -y wget && \
    pip3 install --no-cache-dir -r /opt/kubetools/requirements.txt && \
    if [ "$BUILD_TYPE" = "binary" ]; then \
      apt install -y zlib1g-dev upx-ucl binutils; \
      pip3 install --no-cache-dir pyinstaller;  \
      pyinstaller main.spec --noconfirm;  \
    else \
      wget -O - https://get.helm.sh/helm-v3.7.0-linux-amd64.tar.gz | tar xvz -C /usr/local/bin  linux-amd64/helm --strip-components 1 && \
      [ "$BUILD_TYPE" = "test" ] && pip3 install  --no-cache-dir pytest pylint coverage || true; fi && \
    apt autoremove -y wget zlib1g-dev upx-ucl && \
    apt clean autoclean && \
    rm -f /etc/apt/sources.list && \
    rm -rf /var/lib/apt/lists/*

ENTRYPOINT ["/bin/bash", "/opt/kubetools/kubetools"]