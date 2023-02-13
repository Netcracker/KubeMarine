FROM python:3-slim-buster
# Warning! Python and Debian versions should be strict to avoid sudden components upgrade,
# including unreasonable upgrade of GLIBC version. If the GLIBC version suddenly goes up, a large number of consumers
# will suddenly be unable to use the compiled binary version on older systems.

ARG BUILD_TYPE

ENV PYTHONUNBUFFERED 1

# Used in Ansible plugin. See Ansible documentation for more details
ENV ANSIBLE_HOST_KEY_CHECKING False

COPY . /opt/kubemarine/
WORKDIR /opt/kubemarine/

RUN apt update && \
    pip3 install --no-cache-dir build && \
    python3 -m build -n && \
    # In any if branch delete source code, but preserve specific directories for different service aims
    if [ "$BUILD_TYPE" = "test" ]; then \
      # Install from wheel with ansible to simulate real environment.
      pip3 install --no-cache-dir $(ls dist/*.whl)[ansible]; \
      find -not -path "./test*" -not -path "./examples*" -delete; \
    elif [ "$BUILD_TYPE" = "binary" ]; then \
      # Install from wheel without ansible. This is mostly for installation of dependencies.
      apt install -y zlib1g-dev upx-ucl binutils; \
      pip3 install --no-cache-dir pyinstaller $(ls dist/*.whl); \
      pyinstaller kubemarine.spec --noconfirm; \
      apt autoremove -y zlib1g-dev upx-ucl; \
      find -not -path "./dist*" -delete; \
    elif [ "$BUILD_TYPE" = "package" ]; then \
      find -not -path "./dist*" -delete; \
    else \
      pip3 install --no-cache-dir $(ls dist/*.whl)[ansible]; \
      apt install -y wget; \
      wget -O - https://get.helm.sh/helm-v3.10.0-linux-amd64.tar.gz | tar xvz -C /usr/local/bin  linux-amd64/helm --strip-components 1; \
      apt autoremove -y wget; \
      rm -r *; \
    fi && \
    apt clean autoclean && \
    rm -f /etc/apt/sources.list && \
    rm -rf /var/lib/apt/lists/*

ENTRYPOINT ["kubemarine"]