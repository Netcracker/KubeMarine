FROM python:3.12-slim-bullseye

ARG BUILD_TYPE

ENV PYTHONUNBUFFERED 1

# Used in Ansible plugin. See Ansible documentation for more details
ENV ANSIBLE_HOST_KEY_CHECKING False

COPY . /opt/kubemarine/
WORKDIR /opt/kubemarine/

RUN apt update && \
    # Install Golang and build ipip_check
    apt install -y wget  gcc && \
    wget https://golang.org/dl/go1.19.8.linux-amd64.tar.gz && \
    tar -C /usr/local -xzf go1.19.8.linux-amd64.tar.gz && \
    /usr/local/go/bin/go mod download && \
    GOOS=linux CGO_ENABLED=1 /usr/local/go/bin/go build -ldflags="-linkmode external -extldflags='-static'" -o kubemarine/resources/scripts/ipip_check -buildvcs=false kubemarine/resources/scripts/source/ipip_check/ipip_check.go && \
    rm -Rf /usr/local/go go1.19.8.linux-amd64.tar.gz && \
    apt autoremove -y gcc wget && \
    pip3 install --no-cache-dir build && \
    python3 -m build -n && \
    # In any if branch delete source code, but preserve specific directories for different service aims
    if [ "$BUILD_TYPE" = "test" ]; then \
      # Install from wheel with ansible to simulate real environment.
      pip3 install --no-cache-dir $(ls dist/*.whl)[ansible]; \
      find -not -path "./test*" -not -path "./examples*" -not -path "./scripts*" -delete; \
    elif [ "$BUILD_TYPE" = "package" ]; then \
      find -not -path "./dist*" -delete; \
    else \
      pip3 install --no-cache-dir $(ls dist/*.whl)[ansible]; \
      apt install -y wget; \
      wget -O - https://get.helm.sh/helm-v3.13.2-linux-amd64.tar.gz | tar xvz -C /usr/local/bin  linux-amd64/helm --strip-components 1; \
      apt autoremove -y wget; \
      rm -r *; \
    fi && \
    apt clean autoclean && \
    rm -f /etc/apt/sources.list && \
    rm -rf /var/lib/apt/lists/*

ENTRYPOINT ["kubemarine"]
