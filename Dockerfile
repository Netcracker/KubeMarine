FROM python:3.9-slim-buster AS base

ADD https://get.helm.sh/helm-v3.4.1-linux-amd64.tar.gz /tmp/helm-v3.4.1.tar.gz
RUN tar -zxvf /tmp/helm-v3.4.1.tar.gz && mv linux-amd64/helm /root/helm


FROM python:3.9-slim-buster
# Warning! Python and Debian versions should be strict to avoid sudden components upgrade,
# including unreasonable upgrade of GLIBC version. If the GLIBC version suddenly goes up, a large number of consumers
# will suddenly be unable to use the compiled binary version on older systems.

ARG BUILD_TYPE

USER root

ENV ANSIBLE_HOST_KEY_CHECKING False

COPY . /opt/kubetools/
WORKDIR /opt/kubetools/

COPY --from=base /root/helm /usr/local/bin/helm

RUN apt update && \
    if [ "$BUILD_TYPE" = "binary" ]; then apt install -y zlib1g-dev upx-ucl binutils; fi && \
    pip3 install --no-cache-dir -r /opt/kubetools/requirements.txt && \
    if [ "$BUILD_TYPE" = "test" ]; then pip3 install pytest==5.4.3 pylint coverage; fi && \
    if [ "$BUILD_TYPE" = "binary" ]; then pip3 install pyinstaller; fi && \
    if [ "$BUILD_TYPE" = "binary" ]; then pyinstaller main.spec --noconfirm && exit 0; fi && \
    apt autoremove -y && \
    apt clean autoclean && \
    rm -f /etc/apt/sources.list && \
    rm -rf /var/lib/apt/lists/*

ENTRYPOINT ["/opt/kubetools/kubetools"]
