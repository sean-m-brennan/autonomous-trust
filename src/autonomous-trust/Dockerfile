# syntax=docker/dockerfile:1.3

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
RUN conda create -n autonomous_trust python=3.10 && conda clean -afy

SHELL ["conda", "run", "--live-stream", "-n", "autonomous_trust", "/bin/bash", "-c"]
RUN pip install pydevd-pycharm
RUN --mount=source=dist/conda-repo,target=/app/dist \
    conda install -y -c file:///app/dist autonomous_trust && \
    conda clean -afy

ENV AUTONOMOUS_TRUST_ROOT="/app/config"

COPY autonomous-trust/entrypoint.sh /bin/entrypoint.sh
ENV ROUTER="172.17.0.1"
ENTRYPOINT ["/bin/entrypoint.sh"]