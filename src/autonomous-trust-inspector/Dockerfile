# syntax=docker/dockerfile:1.3
# ******************
#  Copyright 2026 TekFive, Inc., Sean M. Brennan, and contributors
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
# ******************

# AT inspector image: extends the AT-native peer image with Dash
# dependencies and the sibling autonomous_trust.* subpackages
# (evaluation, inspector, services, simulator). Runs the Dash server
# AND an InspectorBridge on the same docker network as the peers so
# it can actually observe them. The default CMD launches the
# multi-agency example; override CMD/ENTRYPOINT to point at a
# different demo entry.
#
# Build from the repo root (context must include src/):
#   docker build -t autonomous-trust-inspector:dev \
#                -f src/autonomous-trust-inspector/Dockerfile .

ARG BASE_IMAGE=autonomous-trust:dev

# ---------------------------------------------------------------------------
# Stage 1: build the async_update Dash component package.
#
# The inspector imports `dash_components.async_update` (core.py:
# "from .async_update import bin_data_pb2"), but that package is generated,
# not committed (see .gitignore) -- so it is absent from the source COPYed
# into the runtime stage, and the dashboard crashes on import without it.
#
# This stage reproduces reactjs/build.sh's *build* steps (build:js +
# build:backends + protoc) on the SAME base image, so the protoc/protobuf
# toolchain and the dash used for wrapper codegen match the runtime. node is
# added via conda-forge; dash is pip-installed only to provide
# `dash-generate-components`. We deliberately skip build.sh's symlink tail and
# instead emit the built package as a plain directory, COPYed into place below.
# ---------------------------------------------------------------------------
FROM ${BASE_IMAGE} AS async-update-builder

ARG http_proxy
ARG https_proxy
ARG no_proxy
# Propagate proxy settings so conda/npm/pip fetches honor them during build.
ENV http_proxy=${http_proxy} https_proxy=${https_proxy} no_proxy=${no_proxy}

USER root

# node/npm drive webpack (build:js) and react-docgen (build:backends);
# dash provides the dash-generate-components entry point used by build:backends.
RUN conda install -y -c conda-forge "nodejs>=18" && conda clean -afy && \
    pip install --no-cache-dir "dash>=4.0.0" pyyaml

WORKDIR /build/reactjs
COPY src/autonomous-trust-inspector/reactjs/ ./

# Reproduce build.sh's build steps. build:js emits async_update.min.js(+map)
# into async_update/; build:backends generates the Python/R/Julia wrappers;
# protoc generates bin_data_pb2.py. The result is a self-contained package
# directory at /build/reactjs/async_update (its own __init__.py serves the JS
# bundle via _js_dist, so no separate assets dir is needed here).
RUN npm install --no-audit --no-fund && \
    npm run build:js && \
    npm run build:backends && \
    protoc -I=async_update --python_out=async_update async_update/bin_data.proto

# ---------------------------------------------------------------------------
# Stage 2: the inspector runtime image.
# ---------------------------------------------------------------------------
FROM ${BASE_IMAGE}

ARG http_proxy
ARG https_proxy
ARG no_proxy

USER root
WORKDIR /app

# Ensure the AT data dir exists for TimedRotatingFileHandler; the base
# image leaves this empty and older automate.py versions don't mkdir
# before opening the logfile.
RUN mkdir -p /var/at /etc/at && chmod 0777 /var/at /etc/at

# Extra Python deps for the Dash-based multi-agency dashboard.
RUN pip install --no-cache-dir \
        "dash>=4.0.0" \
        "dash-bootstrap-components>=2.0.0" \
        "dash-iconify>=0.1.2" \
        "dash-extensions" \
        "plotly>=5.9.0" \
        "flask>=3.0,<3.2" \
        "quart>=0.19.5" \
        "websockets" \
        "networkx>=3.0" \
        "numpy" \
        "scipy" \
        "libsass>=0.22.0" \
        "aenum>=3.1.15" \
        "geopy>=2.4.0" \
        "utm>=0.7.0" \
        "psutil" \
        "ruamel.yaml" \
        "pyyaml" \
        "pillow"

# Overlay the current host source for autonomous_trust.core. The base
# peer image bakes in core at build time, so any post-build fixes
# (e.g. ProcessLogger varargs, automate.py logfile makedirs) would be
# stale without this. The C library at /usr/local/lib is preserved.
COPY src/autonomous-trust/autonomous_trust/core /app/autonomous_trust/core

# Layer the sibling packages via separate PYTHONPATH roots so Python's
# namespace-package mechanism merges autonomous_trust.{core,evaluation,
# inspector,services,simulator} at import time.
COPY src/autonomous-trust-inspector/autonomous_trust   /opt/at-inspector/autonomous_trust
COPY src/autonomous-trust-evaluation/autonomous_trust  /opt/at-evaluation/autonomous_trust
COPY src/autonomous-trust-services/autonomous_trust    /opt/at-services/autonomous_trust
COPY src/autonomous-trust-simulator/autonomous_trust   /opt/at-simulator/autonomous_trust

# The inspector source may carry dash_components/async_update as a build-time
# symlink into reactjs/ (build.sh) -- which is dangling here since reactjs is
# not copied. Drop it, then overlay the real package built in stage 1. Also
# ensure the Dash assets_folder (core.py:160) exists even if empty.
ARG AT_DASH_COMPONENTS=/opt/at-inspector/autonomous_trust/inspector/dash_components
RUN rm -rf "${AT_DASH_COMPONENTS}/async_update" && \
    mkdir -p "${AT_DASH_COMPONENTS}/assets"
COPY --from=async-update-builder /build/reactjs/async_update \
     ${AT_DASH_COMPONENTS}/async_update

# Multi-agency demo lives under examples/, not in the inspector package;
# put it on PYTHONPATH so `python -m examples.multi_agency` resolves.
COPY examples/multi_agency  /opt/examples/multi_agency

ENV PYTHONPATH=/opt/at-inspector:/opt/at-evaluation:/opt/at-services:/opt/at-simulator:/opt:/app

# The base image's entrypoint launches an AT peer daemon; the multi-agency
# inspector runs its own process tree, so clear it.
ENTRYPOINT []
EXPOSE 8050
CMD ["python3", "-m", "examples.multi_agency", \
     "--port", "8050", "--log-level", "info"]
