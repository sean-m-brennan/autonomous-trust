# ******************
#  Copyright 2025 Sean M. Brennan and contributors
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.
# ******************

# Reproducible Buildroot build environment.
# All host toolchain dependencies are pinned in this image.
#
# Usage (called by build-image.sh, not directly):
#   docker build -t at-buildroot -f embedded/buildroot/Dockerfile .
#   docker run --rm -v $(pwd)/embedded:/work at-buildroot

FROM debian:bookworm

ARG http_proxy
ARG https_proxy
ARG no_proxy
ARG CERT_CONTENT

RUN if [ -n "$CERT_CONTENT" ]; then \
      echo "$CERT_CONTENT" > /usr/local/share/ca-certificates/proxy-ca.crt && \
      update-ca-certificates; \
    fi

# Buildroot host dependency list from:
# https://buildroot.org/downloads/manual/manual.html#requirement
RUN apt-get update -y && apt-get install -y --no-install-recommends \
        build-essential \
        bash \
        bc \
        bzip2 \
        cpio \
        file \
        g++ \
        gcc \
        gzip \
        libncurses5-dev \
        make \
        patch \
        perl \
        python3 \
        rsync \
        sed \
        tar \
        unzip \
        wget \
        which \
        xz-utils \
        # U-Boot build dependency
        libssl-dev \
        # dm-verity generation
        cryptsetup \
        # SD image partitioning
        fdisk \
        dosfstools \
        mtools \
        e2fsprogs \
        # misc
        ca-certificates \
        git \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

ARG BR_VERSION=2024.02.10
ARG BR_URL=https://buildroot.org/downloads/buildroot-${BR_VERSION}.tar.xz

# Download and extract Buildroot
WORKDIR /buildroot
RUN wget -q -O buildroot.tar.xz "$BR_URL" && \
    tar -xf buildroot.tar.xz --strip-components=1 && \
    rm buildroot.tar.xz

# /work is the mount point for the embedded/ directory
VOLUME /work

ENTRYPOINT ["/bin/bash", "-c"]
CMD ["echo 'Usage: docker run --rm -v /path/to/embedded:/work at-buildroot \"make ...\"'"]
