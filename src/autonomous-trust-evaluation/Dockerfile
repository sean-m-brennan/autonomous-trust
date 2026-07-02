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

# AT peer image overlay: extends the AT-native peer image with the
# evaluation + services packages so peer containers can launch any
# scenario module under autonomous_trust.evaluation.scenarios (e.g.
# `python -m autonomous_trust.evaluation.scenarios.disaster_response_demo`).
# Without this overlay the base image only ships autonomous_trust.core.
# Reusable across scenarios; the caller chooses the image tag.
#
# Build from the repo root (context must include src/):
#   docker build -t autonomous-trust-peer:dev \
#                -f src/autonomous-trust-evaluation/Dockerfile .

ARG BASE_IMAGE=autonomous-trust:dev
FROM ${BASE_IMAGE}

ARG http_proxy
ARG https_proxy
ARG no_proxy

USER root
WORKDIR /app

# Overlay the current host source for autonomous_trust.core. Mirrors the
# inspector image: any post-build core fixes (ProcessLogger, automate.py
# logfile makedirs) would otherwise be stale here too.
COPY src/autonomous-trust/autonomous_trust/core /app/autonomous_trust/core

# Layer the evaluation + services packages via separate PYTHONPATH roots.
# Python's namespace-package mechanism merges autonomous_trust.{core,
# evaluation,services} at import time. Inspector / simulator are not
# required on a peer.
COPY src/autonomous-trust-evaluation/autonomous_trust  /opt/at-evaluation/autonomous_trust
COPY src/autonomous-trust-services/autonomous_trust    /opt/at-services/autonomous_trust

ENV PYTHONPATH=/opt/at-evaluation:/opt/at-services:/app

# Keep the base image's ENTRYPOINT so STARTUP_DELAY and AUTONOMOUS_TRUST_EXE
# env vars set by the compose generator continue to drive process launch.
