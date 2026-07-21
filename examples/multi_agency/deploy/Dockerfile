# syntax=docker/dockerfile:1.3
# ******************
#  Copyright 2026 TekFive, Inc., Sean M. Brennan, and contributors
#  Licensed under the Apache License, Version 2.0
# ******************

# Multi-agency disaster response demo image.
# Layers the demo code on top of the full AT development stack.
#
# Prerequisites:
#   The base image must be built first:
#     docker build -t autonomous-trust-devel -f src/autonomous-trust/Dockerfile-devel .
#     docker build -t autonomous-trust-full-devel -f src/Dockerfile-devel .
#
# Build (from repo root):
#   docker build -t at-multi-agency-demo -f examples/multi_agency/deploy/Dockerfile .

ARG REGISTRY_URL
ARG IMAGE_TAG
FROM ${REGISTRY_URL}autonomous-trust-full-devel${IMAGE_TAG}

USER root
# Dashboard deps. The coordinator now hosts demo.py (the full inspector
# dashboard) in-thread, so the image needs the same Dash stack the
# autonomous-trust-inspector image ships — notably dash-extensions
# (demo.py: `from dash_extensions...`) and dash-bootstrap-components, plus
# the map/graph deps. Missing dash-extensions makes coordinator.py fail at
# import. (Some may already be in the base image; pip is idempotent.)
SHELL ["conda", "run", "--live-stream", "-n", "autonomous_trust", "/bin/bash", "-c"]
RUN pip install plotly pyyaml dash dash-extensions dash-bootstrap-components \
        networkx numpy geopy utm 2>/dev/null || true
USER user

WORKDIR /app

# Layer the autonomous_trust.evaluation subpackage onto the namespace
# package the base image populates with core/inspector/services/simulator.
# The base image (src/Dockerfile-devel) doesn't include evaluation, but
# the scenario engine, generators, compromise wrappers, and deployment
# helpers all live there.  Without this COPY, the coordinator fails at
# import with `ModuleNotFoundError: No module named 'autonomous_trust.evaluation'`.
COPY --chown=user:user src/autonomous-trust-evaluation/autonomous_trust/evaluation \
                       /app/autonomous_trust/evaluation

# Copy multi-agency demo code
COPY --chown=user:user examples/multi_agency /app/examples/multi_agency

# Ensure examples/ is importable
ENV PYTHONPATH="/app:${PYTHONPATH}"

# Default: show help
CMD ["echo", "Usage: set AUTONOMOUS_TRUST_EXE to participant.py or coordinator.py"]
