FROM python:3.9-slim-buster
# Warning! Python and Debian versions should be strict to avoid sudden components upgrade,
# including unreasonable upgrade of GLIBC version. If the GLIBC version suddenly goes up, a large number of consumers
# will suddenly be unable to use the compiled binary version on older systems.

ARG BUILD_TYPE

USER root

COPY . /opt/kubetools/
WORKDIR /opt/kubetools/

RUN apt update && apt install -y wget && \
    if [ "$BUILD_TYPE" = "binary" ]; then \
      apt install -y zlib1g-dev upx-ucl binutils; \
      pip3 install --no-cache-dir -r /opt/kubetools/requirements.txt; \
      pip3 install pyinstaller;  \
      pyinstaller main.spec --noconfirm;  \
    else \  
      pip3 install --no-cache-dir -r /opt/kubetools/requirements.txt; \
      wget -O - https://get.helm.sh/helm-v3.7.0-linux-amd64.tar.gz | tar xvz -C /usr/local/bin  linux-amd64/helm --strip-components 1 && \
      [ "$BUILD_TYPE" = "test" ] && pip3 install pytest==5.4.3 pylint coverage || true; fi && \
    apt autoremove -y wget zlib1g-dev upx-ucl && \
    apt clean autoclean && \
    rm -f /etc/apt/sources.list && \
    rm -rf /var/lib/apt/lists/*

ENTRYPOINT ["/bin/bash", "/opt/kubetools/kubetools"]
