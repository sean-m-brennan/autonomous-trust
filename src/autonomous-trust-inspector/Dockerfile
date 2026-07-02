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
        "libsass>=0.22.0" \
        "aenum>=3.1.15" \
        "geopy>=2.4.0" \
        "utm>=0.7.0"

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
