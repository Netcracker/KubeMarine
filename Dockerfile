FROM python:3.8.12-slim-buster
# Warning! Python and Debian versions should be strict to avoid sudden components upgrade,
# including unreasonable upgrade of GLIBC version. If the GLIBC version suddenly goes up, a large number of consumers
# will suddenly be unable to use the compiled binary version on older systems.

ARG BUILD_TYPE

USER root

ENV ANSIBLE_HOST_KEY_CHECKING False

COPY . /opt/kubetools/
WORKDIR /opt/kubetools/

# The following dependecies required for cryptography package build (see https://github.com/pyca/cryptography/blob/main/docs/installation.rst)
# - build-essential
# - libssl-dev
# - libffi-dev
# - python3-dev
# - cargo
# Finally they should be removed to avoid big size of docker image

RUN apt update && \
    apt install -y build-essential libssl-dev libffi-dev python3-dev cargo zlib1g-dev && \
    if [ "$BUILD_TYPE" = "binary" ]; then apt install -y upx-ucl binutils; fi && \
    pip3 install --upgrade pip && \
    pip3 install -r /opt/kubetools/requirements.txt && \
    if [ "$BUILD_TYPE" = "test" ]; then pip3 install pytest==5.4.3 pylint coverage; fi && \
    if [ "$BUILD_TYPE" = "binary" ]; then pip3 install pyinstaller; fi && \
    if [ "$BUILD_TYPE" = "binary" ]; then pyinstaller main.spec --noconfirm && exit 0; fi && \
    apt install -y openssl curl && \
    curl -k https://get.helm.sh/helm-v3.4.1-linux-amd64.tar.gz -o helm-v3.4.1.tar.gz && \
    tar -zxvf helm-v3.4.1.tar.gz && \
    mv linux-amd64/helm /usr/local/bin/helm && \
    rm -rf helm-v3.4.1.tar.gz && \
    rm -rf linux-amd64 && \
    apt remove -y build-essential libssl-dev libffi-dev python3-dev cargo && \
    apt autoremove -y && \
    apt clean -y && \
    rm -f /etc/apt/sources.list && \
    rm -rf /var/lib/apt/lists/*

ENTRYPOINT ["/opt/kubetools/kubetools"]
