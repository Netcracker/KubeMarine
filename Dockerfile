# syntax=docker/dockerfile:1

# Build ipip_check binary
FROM golang:1.25.8 AS go-build

WORKDIR /opt

COPY ./kubemarine/resources/scripts/source/ipip_check ./

RUN go mod download && \
    GOOS=linux CGO_ENABLED=1 go build -ldflags="-linkmode external -extldflags='-static'" -o ipip_check -buildvcs=false && \
    gzip ipip_check

FROM alpine:3.23.3 AS helm-downloader
ARG HELM_VERSION=v3.20.0
ADD https://get.helm.sh/helm-${HELM_VERSION}-linux-amd64.tar.gz /tmp/helm.tar.gz
RUN tar -xzf /tmp/helm.tar.gz -C /tmp \
    && mv /tmp/linux-amd64/helm /helm \
    && chmod +x /helm

FROM python:3.13-slim-trixie AS python-build

ARG BUILD_TYPE

ENV PYTHONUNBUFFERED=1

# Used in Ansible plugin. See Ansible documentation for more details
ENV ANSIBLE_HOST_KEY_CHECKING=False

COPY . /opt/kubemarine/
COPY --from=go-build /opt/ipip_check.gz /opt/kubemarine/kubemarine/resources/scripts/
COPY --from=helm-downloader /helm /usr/local/bin/helm
WORKDIR /opt/kubemarine/

RUN apt update && \
    # Ansible uses the local ssh binary by default; install it for ansible plugin execution.
    apt install -y --no-install-recommends openssh-client && \
    python3 -m pip install --upgrade pip && \
    pip3 install --no-cache-dir setuptools wheel build && \
    python3 -m build -n && \
    # In any if branch delete source code, but preserve specific directories for different service aims
    if [ "$BUILD_TYPE" = "test" ]; then \
      pip3 install --no-cache-dir $(ls dist/*.whl)[ansible]; \
      find -not -path "./test*" -not -path "./examples*" -not -path "./scripts*" -delete; \
    elif [ "$BUILD_TYPE" = "package" ]; then \
      find -not -path "./dist*" -delete; \
    else \
      pip3 install --no-cache-dir $(ls dist/*.whl)[ansible]; \
      rm -r *; \
    fi && \
    apt autoremove -y && \
    apt clean && \
    rm -f /etc/apt/sources.list && \
    rm -rf /var/lib/apt/lists/*

ENTRYPOINT ["kubemarine"]
