FROM python:3.9-slim-buster AS base

ADD https://get.helm.sh/helm-v3.7.0-linux-amd64.tar.gz /tmp/helm-v3.7.0.tar.gz
RUN tar -zxvf /tmp/helm-v3.7.0.tar.gz -C /usr/local/bin/ linux-amd64/helm --strip-components 1


FROM python:3.9-slim-buster
# Warning! Python and Debian versions should be strict to avoid sudden components upgrade,
# including unreasonable upgrade of GLIBC version. If the GLIBC version suddenly goes up, a large number of consumers
# will suddenly be unable to use the compiled binary version on older systems.

ARG BUILD_TYPE

USER root

ENV ANSIBLE_HOST_KEY_CHECKING False

COPY . /opt/kubetools/
WORKDIR /opt/kubetools/


RUN apt update && \
    if [ "$BUILD_TYPE" = "binary" ]; then apt install -y zlib1g-dev upx-ucl binutils; fi && \
    pip3 install --no-cache-dir -r /opt/kubetools/requirements.txt && \
    if [ "$BUILD_TYPE" = "test" ]; then pip3 install --no-cache-dir pytest==5.4.3 pylint coverage; fi && \
    if [ "$BUILD_TYPE" = "binary" ]; then pip3 install --no-cache-dir pyinstaller; fi && \
    if [ "$BUILD_TYPE" = "binary" ]; then pyinstaller main.spec --noconfirm && exit 0; fi && \
    apt autoremove -y && \
    apt clean autoclean && \
    rm -f /etc/apt/sources.list && \
    rm -rf /var/lib/apt/lists/*

ENTRYPOINT ["/bin/bash", "/opt/kubetools/kubetools"]