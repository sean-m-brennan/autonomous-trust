# syntax=docker/dockerfile:1.3
# ******************
#  Copyright 2023 TekFive, Inc., Sean M. Brennan, and contributors
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

# Runs pre-built AutonomousTrust

# Prerequisites: (build from repo base dir, context is src)
#   docker build -t package-builder -f src/Dockerfile-build src
#   docker run --rm -u $(id -u):$(id -g) -v $PWD/src/autonomous-trust:/build/src -v $PWD/src/dist/conda-repo:/build/dist -it package-builder
#   docker build -t autonomous-trust -f src/autonomous-trust/Dockerfile src

# Note: conda cannot build with croot inside Docker, must mount to *unencrypted* host filesystem

FROM condaforge/miniforge3

ARG http_proxy
ARG https_proxy
ARG no_proxy
ARG CERT_CONTENT

# Propagate proxy settings so conda run subprocesses inherit them
ENV http_proxy=${http_proxy}
ENV https_proxy=${https_proxy}
ENV no_proxy=${no_proxy}

WORKDIR /app
SHELL ["/bin/bash", "-c"]

# Install CA cert for proxy if provided (must happen before any network access)
RUN if [ -n "$CERT_CONTENT" ]; then \
      echo "$CERT_CONTENT" > /usr/local/share/ca-certificates/proxy-ca.crt && \
      cat /usr/local/share/ca-certificates/proxy-ca.crt >> /etc/ssl/certs/ca-certificates.crt && \
      conda config --set ssl_verify /etc/ssl/certs/ca-certificates.crt; \
    fi
ENV SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt
ENV REQUESTS_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt

RUN apt-get update && \
    apt-get install -y iproute2 iputils-ping iputils-arping iputils-tracepath nfs-common sudo curl jq && \
    apt-get clean

#RUN useradd -U user -d /app
RUN echo "ALL            ALL = (ALL) NOPASSWD: ALL" >>/etc/sudoers
#RUN chown -R user:user /app
#COPY --chown=user:user autonomous-trust/.bashrc /app/.bashrc

RUN conda config --add channels conda-forge
RUN conda update -y -n base conda
RUN conda create -n autonomous_trust python=3.13 && conda clean -afy

SHELL ["conda", "run", "--live-stream", "-n", "autonomous_trust", "/bin/bash", "-c"]
RUN pip install pydevd-pycharm
RUN --mount=source=dist/conda-repo,target=/app/dist \
    conda install -y -c file:///app/dist autonomous_trust && \
    conda clean -afy

ENV AUTONOMOUS_TRUST_ROOT="/app/config"

COPY autonomous-trust/entrypoint.sh /bin/entrypoint.sh
ENV ROUTER="172.17.0.1"
ENTRYPOINT ["/bin/entrypoint.sh"]